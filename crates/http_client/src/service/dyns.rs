// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Defines standard `dyn` API that most things can be converted to.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures::TryFutureExt;
use http::{Request, Response};
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Body, Frame, SizeHint};
use hyper::service::Service;

use super::HttpService;
use super::util::ServiceFn;

/// Wrapper for boxed dynamic [`HttpService`].
///
/// The advantage of this over a simple `dyn HttpService<...>` is that it also boxes request
/// bodies (allowing it to implement [`Service`] over a wider range of [`Body`] types), the
/// returned future and response bodies.
pub struct ArcedHttpService<FutureErr = BoxedError, BodyErr = FutureErr>(
    Arc<DynHttpService<FutureErr, BodyErr>>,
);

/// Wrapper for boxed dynamic [`HttpService`].
///
/// The advantage of this over a simple `dyn HttpService<...>` is that it also boxes request
/// bodies (allowing it to implement [`Service`] over a wider range of [`Body`] types), the
/// returned future and response bodies.
pub struct BoxedHttpService<FutureErr = BoxedError, BodyErr = FutureErr>(
    Box<DynHttpService<FutureErr, BodyErr>>,
);

pub type DynHttpService<FutureErr, BodyErr> = dyn Service<
        Request<BoxedBody>,
        Future = BoxedFuture<FutureErr, BodyErr>,
        Response = Response<BoxedBody<BodyErr>>,
        Error = FutureErr,
    > + Send
    + Sync;

type BoxedFuture<FutureErr, BodyErr> =
    Pin<Box<dyn Future<Output = Result<Response<BoxedBody<BodyErr>>, FutureErr>> + Send>>;

pub type BoxedBody<BodyErr = BoxedError> = UnsyncBoxBody<Bytes, BodyErr>;

pub type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Convenience trait for [`HttpService`]s that are compatible with [`DynHttpService`].
pub trait IntoDynHttpService<FutureErr = BoxedError, BodyErr = FutureErr>:
    HttpService<
        BoxedBody<BoxedError>,
        Future: Send,
        ResponseBody: Body<Error: Into<BodyErr>> + Send,
        Error: Into<FutureErr>,
    > + Send
    + Sync
    + 'static
{
}

impl<S, FutureErr, BodyErr> IntoDynHttpService<FutureErr, BodyErr> for S
where
    S: HttpService<BoxedBody> + Send + Sync + 'static,
    S::Future: Send,
    S::ResponseBody: Send,
    <S::ResponseBody as Body>::Error: Into<BodyErr>,
    S::Error: Into<FutureErr>,
{
}

/// Completely put service behind `dyn` [`Arc`], including errors it returns.
///
/// If you want to customize the error type, use [`ArcedHttpService::new`] instead.
pub fn arced(service: impl IntoDynHttpService) -> ArcedHttpService {
    ArcedHttpService::new(service)
}

impl<FutureErr, BodyErr> ArcedHttpService<FutureErr, BodyErr> {
    /// Arc the given service.
    ///
    /// Note that you may need to specify the error types used by the [`ArcedHttpService`].
    /// For convenience, there is a [`arced`] function that uses [`BoxedError`]s for everything.
    pub fn new<S>(service: S) -> Self
    where
        S: IntoDynHttpService<FutureErr, BodyErr>,
        FutureErr: 'static,
        BodyErr: 'static,
    {
        // Don't daisy-chain boxes if we're given the same type we'll return.
        let service = match try_downcast_into(service) {
            Ok(service) => return service,
            Err(service) => service,
        };
        // Allow converting dyn boxes to dyn arcs without daisy-chaining.
        let service = match try_downcast_into(service) {
            Ok(BoxedHttpService(service)) => return Self(service.into()),
            Err(service) => service,
        };

        Self(Arc::new(ServiceFn(move |request| {
            box_future(service.send(request))
        })))
    }
}

impl<B, FutureErr, BodyErr> Service<Request<B>> for ArcedHttpService<FutureErr, BodyErr>
where
    B: Body + Send + 'static,
    B::Error: Into<BoxedError>,
{
    type Future = BoxedFuture<FutureErr, BodyErr>;
    type Response = Response<BoxedBody<BodyErr>>;
    type Error = FutureErr;

    fn call(&self, request: Request<B>) -> Self::Future {
        self.0
            .call(request.map(|body| box_body(body.map_err(Into::into))))
    }
}

impl<FutureErr, BodyErr> Clone for ArcedHttpService<FutureErr, BodyErr> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Completely put service behind `dyn` [`Box`], including errors it returns.
///
/// If you want to customize the error type, use [`BoxedHttpService::new`] instead.
pub fn boxed(service: impl IntoDynHttpService) -> BoxedHttpService {
    BoxedHttpService::new(service)
}

impl<FutureErr, BodyErr> BoxedHttpService<FutureErr, BodyErr> {
    /// Box the given service.
    ///
    /// Note that you may need to specify the error types used by the [`BoxedHttpService`].
    /// For convenience, there is a [`boxed`] function that uses [`BoxedError`]s for everything.
    pub fn new<S>(service: S) -> Self
    where
        S: IntoDynHttpService<FutureErr, BodyErr>,
        FutureErr: 'static,
        BodyErr: 'static,
    {
        // Don't daisy-chain boxes if we're given the same type we'll return.
        let service = match try_downcast_into(service) {
            Ok(service) => return service,
            Err(service) => service,
        };

        Self(Box::new(ServiceFn(move |request| {
            box_future(service.send(request))
        })))
    }
}

impl<B, FutureErr, BodyErr> Service<Request<B>> for BoxedHttpService<FutureErr, BodyErr>
where
    B: Body + Send + 'static,
    B::Error: Into<BoxedError>,
{
    type Future = BoxedFuture<FutureErr, BodyErr>;
    type Response = Response<BoxedBody<BodyErr>>;
    type Error = FutureErr;

    fn call(&self, request: Request<B>) -> Self::Future {
        self.0
            .call(request.map(|body| box_body(body.map_err(Into::into))))
    }
}

fn box_future<F, B, E, FutureErr, BodyErr>(future: F) -> BoxedFuture<FutureErr, BodyErr>
where
    F: Future<Output = Result<Response<B>, E>> + Send + 'static,
    B: Body + Send + 'static,
    <B as Body>::Error: Into<BodyErr>,
    E: Into<FutureErr> + 'static,
    FutureErr: 'static,
    BodyErr: 'static,
{
    // Don't daisy-chain Futures if we're given the same type we'll return.
    let future = match try_downcast_into(future) {
        Ok(future) => return future,
        Err(future) => future,
    };

    let future = future
        .map_ok(|response| response.map(box_body))
        .map_err(Into::into);
    Box::pin(future) as _
}

fn box_body<B, E>(body: B) -> BoxedBody<E>
where
    B: Body + Send + 'static,
    B::Error: Into<E>,
    E: 'static,
{
    // Don't daisy-chain Bodies if we're given the same type we'll return.
    let body = match try_downcast_into(body) {
        Ok(body) => return body,
        Err(body) => body,
    };

    BytesBody(body).map_err(Into::into).boxed_unsync()
}

// `BytesBody(body)` is equivalent to:
// body.map_frame(|frame| frame.map_data(|mut buf| buf.copy_to_bytes(buf.remaining())))
// except it doesn't obliterate the size hint
#[pin_project::pin_project]
struct BytesBody<B>(#[pin] B);

impl<B: Body> Body for BytesBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        ctx: &mut Context,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.project().0.poll_frame(ctx);
        result.map_ok(|frame| frame.map_data(|mut buf| buf.copy_to_bytes(buf.remaining())))
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

// Cast T to U if T == U, otherwise return T. Should be completely optimized away.
// Technique shamelessly stolen from `http` crate's `if_downcast_into!`.
fn try_downcast_into<T: std::any::Any, U: 'static>(t_val: T) -> Result<U, T> {
    let mut t_holder = Some(t_val); // allows moving t_val out from behind a &mut
    match <dyn std::any::Any>::downcast_mut::<Option<U>>(&mut t_holder) {
        Some(u_holder) => Ok(u_holder.take().unwrap()),
        None => Err(t_holder.unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures::FutureExt;

    use tokio::sync::mpsc;

    struct QueueBody<D, E>(mpsc::Receiver<Result<Frame<D>, E>>);

    impl<D: Buf, E> Body for QueueBody<D, E> {
        type Data = D;
        type Error = E;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Option<Result<Frame<D>, E>>> {
            self.0.poll_recv(cx)
        }
    }

    async fn echo_service<B>(request: http::Request<B>) -> Result<Response<B>, Infallible> {
        Ok(Response::new(request.into_body()))
    }

    #[tokio::test]
    async fn arcing_doesnt_change_body_output() {
        body_output_is_unchanged(arced(ServiceFn(echo_service))).await;
    }

    #[tokio::test]
    async fn boxing_doesnt_change_body_output() {
        body_output_is_unchanged(boxed(ServiceFn(echo_service))).await;
    }

    async fn body_output_is_unchanged(
        echo_service: impl HttpService<
            QueueBody<&[u8], &str>,
            ResponseBody = BoxedBody,
            Error = BoxedError,
        >,
    ) {
        let (tx, rx) = mpsc::channel(4);
        let request = Request::new(QueueBody(rx));
        let response = echo_service.send(request).await.unwrap();
        let mut res_body = response.into_body();

        assert!(res_body.frame().now_or_never().is_none());

        tx.send(Ok(Frame::data(&b"This is"[..]))).await.unwrap();
        let frame = res_body.frame().now_or_never().unwrap().unwrap().unwrap();
        assert_eq!(*frame.into_data().unwrap(), *b"This is");

        tx.send(Ok(Frame::data(&b" a test."[..]))).await.unwrap();
        let frame = res_body.frame().now_or_never().unwrap().unwrap().unwrap();
        assert_eq!(*frame.into_data().unwrap(), *b" a test.");

        assert!(res_body.frame().now_or_never().is_none());

        tx.send(Err("Oh no!")).await.unwrap();
        let frame = res_body.frame().now_or_never().unwrap().unwrap();
        assert_eq!(frame.unwrap_err().to_string(), "Oh no!");

        drop(tx);
        assert!(res_body.frame().now_or_never().unwrap().is_none());
    }

    // It's sorely tempting to simplify a lot of code by getting rid of BytesBody...
    // These two tests exist to prevent that.
    // We need size-hints to give proper content lengths.

    #[tokio::test]
    async fn arcing_retains_size_hints() {
        let echo_service = arced(ServiceFn(echo_service));
        let request = Request::new("Hello, world!".to_owned());
        let response = echo_service.send(request).await.unwrap();
        let size_hint = response.body().size_hint().exact();
        assert_eq!(size_hint, Some(13));
    }

    #[tokio::test]
    async fn boxing_retains_size_hints() {
        let echo_service = boxed(ServiceFn(echo_service));
        let request = Request::new("Hello, world!".to_owned());
        let response = echo_service.send(request).await.unwrap();
        let size_hint = response.body().size_hint().exact();
        assert_eq!(size_hint, Some(13));
    }

    #[tokio::test]
    async fn arcing_propagates_service_errors() {
        let broken_service = arced(ServiceFn::http(|_| async {
            Err::<Response<String>, _>("Everything's b0rked.")
        }));
        let request = Request::new("".to_owned());
        let err = broken_service.send(request).await.unwrap_err();
        assert_eq!(err.to_string(), "Everything's b0rked.");
    }

    #[tokio::test]
    async fn boxing_propagates_service_errors() {
        let broken_service = boxed(ServiceFn::http(|_| async {
            Err::<Response<String>, _>("Everything's b0rked.")
        }));
        let request = Request::new("".to_owned());
        let err = broken_service.send(request).await.unwrap_err();
        assert_eq!(err.to_string(), "Everything's b0rked.");
    }

    #[test]
    fn arcing_is_idempotent() {
        // We're checking that boxed(boxed(foo)) == boxed(foo).
        // That'd be nice so APIs can just always-box stuff without being wasteful
        // if things are already boxed. Thankfully, coercing a `&dyn Trait` to
        // `*const dyn Trait` yields a pointer to its data, giving us a way to
        // see if boxing wrapped something in another allocation despite all other
        // observable behavior being identical.

        let msg = "hello";
        let greet = ServiceFn(move |_request: Request<_>| async move {
            Ok::<_, Infallible>(Response::new(msg.to_owned()))
        });

        let service = arced(greet);
        let addr1 = (&*service.0) as *const _;

        // In order for this test to work, `greet` can't be a ZST, because they
        // can share a dummy data pointer to 0x01, so they'll pass this test even
        // if our code daisy-chains boxes.
        assert_ne!(
            addr1,
            (&*arced(greet).0) as *const _,
            "the test setup is broken: `greet` shouldn't be a ZST but likely is."
        );

        let service = arced(service.clone());
        let addr2 = (&*service.0) as *const _;
        assert_eq!(
            addr1, addr2,
            "arcing `arced(greet)` shouldn't change its memory location"
        );
    }

    #[test]
    fn boxing_is_idempotent() {
        // We're checking that boxed(boxed(foo)) == boxed(foo).
        // That'd be nice so APIs can just always-box stuff without being wasteful
        // if things are already boxed. Thankfully, coercing a `&dyn Trait` to
        // `*const dyn Trait` yields a pointer to its data, giving us a way to
        // see if boxing wrapped something in another allocation despite all other
        // observable behavior being identical.

        let msg = "hello";
        let greet = ServiceFn(move |_request: Request<_>| async move {
            Ok::<_, Infallible>(Response::new(msg.to_owned()))
        });

        let service = boxed(greet);
        let addr1 = (&*service.0) as *const _;

        // In order for this test to work, `greet` can't be a ZST, because they
        // can share a dummy data pointer to 0x01, so they'll pass this test even
        // if our code daisy-chains boxes.
        assert_ne!(
            addr1,
            (&*boxed(greet).0) as *const _,
            "the test setup is broken: `greet` shouldn't be a ZST but likely is."
        );

        let service = boxed(service);
        let addr2 = (&*service.0) as *const _;
        assert_eq!(
            addr1, addr2,
            "boxing `boxed(greet)` shouldn't change its memory location"
        );
    }
}
