// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Defines adapter for running [`HttpService`] in another future

use std::pin::{Pin, pin};
use std::task::{Context, Poll, ready};

use futures::{Stream, StreamExt};
use http::{Request, Response};
use hyper::body::{Body, Frame, SizeHint};

use super::HttpService;
use super::util::ServiceFn;

// Note: We use async_channel because I'd like this to be one less thing that's runtime dependent.

struct OutsourcedHttpRequest<B, S: HttpService<B>> {
    request: Request<B>,
    response_capacity: usize,
    response_channel: ResponseChannel<S::ResponseBody, S::Error>,
}

type ResponseChannel<B, E> = async_channel::Sender<Result<Response<OutsourcedBody<B>>, E>>;

/// Creates a [`Send`]able [`HttpService`] that communicates with given `service` via channels.
///
/// This is used to work around [`reqwest`] types not being [`Send`] on WASM. Given a
/// non-[`Send`] `sevice`, this returns:
/// * An "outsourced" [`HttpService`]; it is [`Send`]able, cheaply [`Clone`]able, and
///   hands off all work to the given `service` via channels.
/// * A "worker" [`Future`] that runs `service` to handle requests for the outsourced
///   [`HttpService`]. The [`Future`] will resolve when there are no clones if its
///   associated outsourced [`HttpService`].
///
/// # Panics
///
/// It is an error to use an outsourced [`HttpService`] if its associated [`Future`]
/// has been dropped; that may result in a panic. This can easily be avoided by running
/// the associated [`Future`] to completion.
///
/// # Performance Caveats
///
/// This creates two channels per request... probably not a big deal as we're not
/// spamming requests.
///
/// Request bodies are currently processed in the worker [`Future`], so it may not be
/// ideal to do much work in them. On the other hand, this is likely to be used in
/// single-threaded environments, so perhaps that doesn't matter.
///
/// Response bodies have their [`size_hint`](Body::size_hint) polled after every frame,
/// so that needs to be kept cheap.
pub fn outsourced<B, S>(
    service: S,
) -> (
    impl HttpService<
        B,
        Future: Send + 'static,
        ResponseBody = OutsourcedBody<S::ResponseBody>,
        Error = S::Error,
    > + Clone,
    impl Future<Output = ()>,
)
where
    B: Send + 'static,
    S: HttpService<B> + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
    S::Error: Send,
{
    // Why go with a default response capacity of 1? This adapter is likely to be used in
    // WASM (read: single-threaded) environments, so having multiple slots won't increase
    // parallelism, and having large buffers can cause their own problems...
    let response_capacity = 1;
    outsourced_with_response_capacity(service, response_capacity)
}

/// Creates a [`Send`]able [`HttpService`] that communicates with given `service` via channels.
///
/// This is like [`outsourced`], except it allows specifying the number of response frames
/// that may be queued up.
pub fn outsourced_with_response_capacity<B, S>(
    service: S,
    response_capacity: usize,
) -> (
    impl HttpService<
        B,
        Future: Send + 'static,
        ResponseBody = OutsourcedBody<S::ResponseBody>,
        Error = S::Error,
    > + Clone,
    impl Future<Output = ()>,
)
where
    B: Send + 'static,
    S: HttpService<B> + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
    S::Error: Send,
{
    let (requests_tx, requests_rx) = async_channel::bounded(4);
    (
        outsourced_http_service(requests_tx, response_capacity),
        serve_outsourced_requests(service, requests_rx),
    )
}

// Returns HttpService that sends requests through `requests_tx`.
fn outsourced_http_service<B, S>(
    requests_tx: async_channel::Sender<OutsourcedHttpRequest<B, S>>,
    response_capacity: usize,
) -> impl HttpService<
    B,
    Future: Send + 'static,
    ResponseBody = OutsourcedBody<S::ResponseBody>,
    Error = S::Error,
> + Clone
where
    B: Send + 'static,
    S: HttpService<B> + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
    S::Error: Send,
{
    ServiceFn::new(move |request: Request<_>| {
        let request_tx = requests_tx.clone();
        async move {
            let (response_tx, response_rx) = async_channel::bounded(1);
            let outsourced_request = OutsourcedHttpRequest {
                request,
                response_capacity,
                response_channel: response_tx,
            };
            request_tx
                .send(outsourced_request)
                .await
                .expect("Outsourced service used after background task dropped.");
            response_rx
                .recv()
                .await
                .expect("Outsourced service used after background task dropped.")
        }
    })
}

// Accepts incoming requests over `requests_rx`, executes them via `service` and sends the
// responses back via each request's `oneshot::Sender`s. All requests/responses are handled
// concurrently with one another.
async fn serve_outsourced_requests<B, S: HttpService<B>>(
    service: S,
    requests_rx: async_channel::Receiver<OutsourcedHttpRequest<B, S>>,
) {
    let service = &service;
    requests_rx
        .for_each_concurrent(None, |outsourced_request| async move {
            let OutsourcedHttpRequest {
                request,
                response_capacity,
                response_channel,
            } = outsourced_request;

            let send_request = service.send(request);
            let is_closed = || response_channel.is_closed();
            match do_unless(send_request, is_closed).await {
                Some(Ok(response)) => {
                    let (parts, body) = response.into_parts();
                    let (body, send_to_body) =
                        OutsourcedBody::new_with_capacity(body, response_capacity);
                    let response = Response::from_parts(parts, body);
                    // If this fails to send, it just means the response was aborted; that's fine.
                    let _ = response_channel.send(Ok(response)).await;
                    send_to_body.await;
                }
                Some(Err(err)) => {
                    // If this fails to send, it just means the response was aborted; that's fine.
                    let _ = response_channel.send(Err(err)).await;
                }
                None => {} // Request was aborted while servicing it
            }
        })
        .await;
}

async fn do_unless<T>(
    action: impl Future<Output = T>,
    mut should_stop: impl FnMut() -> bool,
) -> Option<T> {
    let mut action = pin!(action);
    std::future::poll_fn(|cx| {
        if should_stop() {
            return Poll::Ready(None);
        }
        action.as_mut().poll(cx).map(Some)
    })
    .await
}

// Body that gets its frames and state over a channel.
// Note: Checks size_hint after every frame
#[pin_project::pin_project]
pub struct OutsourcedBody<B: Body> {
    #[pin]
    body_updates: async_channel::Receiver<OutsourcedBodyUpdate<B>>,
    size_hint: SizeHint,
}

struct OutsourcedBodyUpdate<B: Body> {
    frame: Option<Result<Frame<B::Data>, B::Error>>,
    size_hint: SizeHint,
}

impl<B: Body> OutsourcedBody<B> {
    // Given a `body`, returns an `OutsourcedBody` and sender `Future`.
    // The sender `Future` holds the `body` and transmits it to `OutsourcedBody` over a channel.
    // Though the sender Future may not be Send + Sync, the `OutsourcedBody` should be.
    fn new_with_capacity(body: B, capacity: usize) -> (Self, impl Future) {
        let (body_updates_tx, body_updates_rx) = async_channel::bounded(capacity);
        let this = Self {
            body_updates: body_updates_rx,
            size_hint: body.size_hint(),
        };
        (this, Self::send_to_body(body, body_updates_tx))
    }

    // Repeatedly polls `body`, sending updates over `body_update_tx`.
    async fn send_to_body(body: B, body_updates: async_channel::Sender<OutsourcedBodyUpdate<B>>) {
        let mut body = pin!(body);
        while let Some(frame) = std::future::poll_fn(|ctx| body.as_mut().poll_frame(ctx)).await {
            let update = OutsourcedBodyUpdate {
                frame: Some(frame),
                size_hint: body.size_hint(),
            };
            if body_updates.send(update).await.is_err() {
                // The OutsourcedBody is allowed to be dropped...
                // No point sending more updates if that happens.
                return;
            }
        }
        let update = OutsourcedBodyUpdate {
            frame: None,
            size_hint: SizeHint::with_exact(0),
        };
        // Again, no worries if the OutsourcedBody was dropped...
        let _ = body_updates.send(update).await;
    }
}

impl<B: Body> Body for OutsourcedBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.is_end_stream() {
            return Poll::Ready(None);
        }
        let this = self.project();
        let update = ready!(this.body_updates.poll_next(cx))
            .expect("Worker Future was dropped before OutsourcedBody");
        *this.size_hint = update.size_hint;
        Poll::Ready(update.frame)
    }

    fn is_end_stream(&self) -> bool {
        self.size_hint.exact() == Some(0)
    }

    fn size_hint(&self) -> SizeHint {
        self.size_hint.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::marker::PhantomData;

    use http_body_util::BodyExt;

    use super::super::util::boxed;

    type Unsendable = PhantomData<*const ()>;

    fn unsendable() -> Unsendable {
        PhantomData
    }

    // TODO: Revert back to a simple `body.map_err(|e| { let _x = unsendable(); e})`
    // once https://github.com/rust-lang/rust/issues/148511 is fixed.
    #[pin_project::pin_project]
    struct UnsendableBody<B> {
        #[pin]
        inner: B,
        unsendable: Unsendable,
    }

    impl<B> UnsendableBody<B> {
        fn new(inner: B) -> Self {
            Self {
                inner,
                unsendable: unsendable(),
            }
        }
    }

    impl<B: Body> Body for UnsendableBody<B> {
        type Data = B::Data;
        type Error = B::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.project().inner.poll_frame(cx)
        }

        fn size_hint(&self) -> SizeHint {
            self.inner.size_hint()
        }
    }

    // Technically, this is going slightly overboard as Rust won't automatically infer that
    // the HttpService's associated types are sendable, but I'd like to ensure that improvements
    // to type inference can't render any of this sendable.
    //
    // We still make the Response's Body's Data and any errors sendable because `outsourced`
    // needs that, but most things provide that in practice; `String`s and `Bytes` are sendable.
    fn unsendable_echo_service<B: Body>()
    -> impl HttpService<B, ResponseBody = UnsendableBody<B>, Error = Infallible> {
        let _unsendable = unsendable();
        ServiceFn(move |request: Request<B>| {
            // Make the `Service` itself unsendable by pulling in `unsendable`.
            let _unsendable = unsendable();
            async move {
                let body = UnsendableBody::new(request.into_body());
                // Make the Service's future unsendable by holding the unsendable body
                // across an await point.
                tokio::task::yield_now().await;
                Ok(Response::new(body))
            }
        })
    }

    fn assert_send(_: &impl Send) {}

    #[tokio::test]
    async fn outsourcing_makes_everything_sendable() {
        let (service, handle_requests) = outsourced(unsendable_echo_service());
        assert_send(&service);

        let tests = async move {
            let request = Request::new("Hello world!".to_owned());
            let response_future = service.send(request);
            assert_send(&response_future);

            let body = response_future.await.unwrap().into_body();
            assert_send(&body);

            let Ok(collected) = body.collect().await;
            assert_eq!(collected.to_bytes(), &b"Hello world!"[..]);
        };
        tokio::join!(tests, handle_requests);
    }

    #[tokio::test]
    async fn outsourcing_retains_size_hints() {
        let (service, handle_requests) = outsourced(unsendable_echo_service());
        let tests = async move {
            let request = Request::new("Hello world!".to_owned());
            let body = service.send(request).await.unwrap().into_body();
            assert_eq!(body.size_hint().exact(), Some(12));
        };
        tokio::join!(tests, handle_requests);
    }

    #[tokio::test]
    async fn sanity_check_outsourcing_and_boxing_can_be_chained() {
        let (service, handle_requests) = outsourced(unsendable_echo_service());
        let service = boxed(service);
        let tests = async move {
            let body1 = "Hello world!".to_owned();
            let request1 = Request::new(body1);
            let body2 = service.send(request1).await.unwrap().into_body();
            let request2 = Request::new(body2);
            let body3 = service.send(request2).await.unwrap().into_body();
            let msg = body3.collect().await.unwrap().to_bytes();
            assert_eq!(msg, &b"Hello world!"[..]);
        };
        tokio::join!(tests, handle_requests);
    }
}
