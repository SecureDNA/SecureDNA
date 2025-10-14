// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Utilities for using [`reqwest`] as an [`HttpService`]

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures::TryStreamExt;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use reqwest::RequestBuilder;

use super::util::ServiceFn;
use super::HttpService;

/// From [`reqwest`]:
pub use reqwest::Client;

/// [`HttpService`] adapter that sends requests through [`reqwest::Client`]
///
/// This supports bidirectional streaming, but is only available on non-WASM platforms.
#[cfg(not(target_arch = "wasm32"))]
pub fn native_service<ReqBody>(
    client: reqwest::Client,
) -> impl HttpService<
    ReqBody,
    Future: Send + 'static,
    ResponseBody: Body<Data = Bytes, Error = reqwest::Error> + Send + Sync,
    Error = reqwest::Error,
>
where
    ReqBody: Body + Send + 'static,
    ReqBody::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    use bytes::Buf;
    use http::header::CONTENT_LENGTH;

    ServiceFn(move |mut request: http::Request<ReqBody>| {
        let client = client.clone();
        async move {
            if let Some(content_length) = request.body().size_hint().exact() {
                request
                    .headers_mut()
                    .entry(CONTENT_LENGTH)
                    .or_insert(content_length.into());
            }
            let to_reqwest_body = |body: ReqBody| {
                let body = body
                    .into_data_stream()
                    .map_ok(|mut buf| buf.copy_to_bytes(buf.remaining()));
                reqwest::Body::wrap_stream(body)
            };
            let request = request.map(to_reqwest_body).try_into()?;

            let response = client.execute(request).await?;
            let remaining_size = response.content_length();
            Ok(http::Response::from(response).map(|body| SizedBody {
                body,
                remaining_size,
            }))
        }
    })
}

/// [`HttpService`] adapter that sends requests through [`reqwest::Client`]
///
/// This is WASM-compatible at the cost of two major drawbacks:
/// * The returned [`HttpService`] might not be [`Send`]able. Any futures and responses returned
///   by said [`HttpService`] won't be [`Send`]able.
/// * This doesn't support request body streaming; request bodies will be preemptively collected
///   before starting to send the request.
///
/// When running in a browser, this respects [`BrowserFetchSettings`]. However,
/// [`reqwest`] doesn't seem to handle disabling CORS very well; it errors out if
/// accessing e.g. the URL fails (which it will for cross-origin requests without CORS).
pub fn compatible_service<ReqBody>(
    client: reqwest::Client,
) -> impl HttpService<
    ReqBody,
    ResponseBody: Body<Data = Bytes, Error = reqwest::Error>,
    Error = reqwest::Error,
>
where
    ReqBody: Body,
    // Currently superfluous on WASM, but I want to know if anything is unable to meet this,
    // to ensure future improvements will be possible.
    ReqBody::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    use http_body_util::StreamBody;

    ServiceFn(move |request: hyper::Request<ReqBody>| {
        let client = client.clone();
        async move {
            let browser_fetch_settings =
                BrowserFetchSettings::from_request(&request).unwrap_or_default();
            let (parts, body) = request.into_parts();
            let body = body.collect().await.map_err(reqwest_err)?.to_bytes();
            // It'd be nice to use the conversion from `http::Request` to `reqwest::Request`,
            // but then I can't use RequestBuilder to adjust fetch-credentials settings. Oh well.
            let request = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body);
            let request = browser_fetch_settings.apply_to_request_builder(request);
            let mut response = request.send().await?;

            // The reqwest::Response -> hyper::Response conversion doesn't exist on WASM. :(
            let mut builder = hyper::Response::builder().status(response.status());
            if let Some(headers) = builder.headers_mut() {
                *headers = std::mem::take(response.headers_mut());
            }
            let remaining_size = response.content_length();
            let stream = response.bytes_stream();
            let body = SizedBody {
                body: StreamBody::new(stream.map_ok(Frame::data)),
                remaining_size,
            };
            let response = builder
                .body(body)
                .expect("a valid reqwest::Request should be a valid hyper::Request");
            Ok(response)
        }
    })
}

// This is terrible. I need to go back and eventually find a better approach. :(
// The native reqwest impl only needs reqwest::Error, and any errors during body generation
// get wrapped in reqwest::Error by reqwest. Under WASM, reqwest doesn't handle streaming
// bodies, and there's no way to get it to generate a reqwest::Error if body generation fails.
// So my options are:
// * Spend a bunch of time building out a whole new error type just for one WASM-specific
//   edge case that may go away if reqwest eventually gains streaming support under WASM.
// * Generate a dummy reqwest::Error from some other cause, and come back to this when I have
//   more time.
// I've opted for the latter approach.
fn reqwest_err<T>(_: T) -> reqwest::Error {
    // Mainly including this because if the error gets propagated, I worry the URL error
    // will be super confusing. :/
    tracing::warn!("Couldn't collect request body; returning URL error.");

    reqwest::Client::new()
        .request(reqwest::Method::GET, "Not a URL: Body generation failed.")
        .build()
        .expect_err("should error due to invalid URL")
}

// Allows adding a size_hint to a body that doesn't otherwise support it.
// We use this because e.g. converting a reqwest::Response to an http::Response doesn't properly
// retain size_hints from content-length.
#[pin_project::pin_project]
struct SizedBody<B> {
    #[pin]
    body: B,
    remaining_size: Option<u64>,
}

impl<B: Body> Body for SizedBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        this.body
            .poll_frame(cx)
            .map_ok(|frame| {
                if let Some(data) = frame.data_ref() {
                    *this.remaining_size = this.remaining_size.and_then(|body_size| {
                        let data_size = data.remaining().try_into().ok()?;
                        body_size.checked_sub(data_size)
                    });
                }
                frame
            })
            .map_err(|err| {
                *this.remaining_size = None;
                err
            })
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        match self.remaining_size {
            Some(size) => SizeHint::with_exact(size),
            None => self.body.size_hint(),
        }
    }
}

/// Describes how browsers should send requests.
///
/// Browsers need to be told whether to use CORS and whether to send credentials.
/// This affects the behavior of [`compatible_service`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BrowserFetchSettings {
    /// Corresponds with the request's [`mode`] attribute in javascript.
    ///
    /// Selects between `cors` and `no-cors`, defaulting to `cors` (`true`).
    /// Beware that [`reqwest`] doesn't yet handle `no-cors` gracefully for cross-origin
    /// requests as it'll error out due to being unable to access the response URL.
    ///
    /// [`mode`]: https://developer.mozilla.org/en-US/docs/Web/API/Request/mode
    pub use_cors: bool,
    /// Corresponds with the request's [`credentials`] attribute in javascript.
    ///
    /// [`credentials`]: https://developer.mozilla.org/en-US/docs/Web/API/Request/credentials
    pub fetch_credentials: FetchCredentials,
}

/// Determines whether a browser should include credentials with a request.
///
/// This indicates which [request `credentials`] should be used. It's applied via
/// [`BrowserFetchSettings`].
///
/// [request `credentials`]: https://developer.mozilla.org/en-US/docs/Web/API/Request/credentials
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum FetchCredentials {
    /// Corresponds with a request `credentials` of `same-origin`.
    ///
    /// This is the default.
    #[default]
    SameOrigin,
    /// Corresponds with a request `credentials` of `include`.
    Include,
    /// Corresponds with a request `credentials` of `omit`.
    Omit,
}

impl Default for BrowserFetchSettings {
    fn default() -> Self {
        Self {
            use_cors: true,
            fetch_credentials: Default::default(),
        }
    }
}

impl BrowserFetchSettings {
    /// Return copy with [`use_cors`](Self::use_cors) enabled.
    pub fn with_cors(self) -> Self {
        Self {
            use_cors: true,
            ..self
        }
    }

    /// Return copy with [`use_cors`](Self::use_cors) disabled.
    pub fn without_cors(self) -> Self {
        Self {
            use_cors: false,
            ..self
        }
    }

    /// Return copy with [`fetch_credentials`](Self::fetch_credentials) set to
    /// [`SameOrigin`](FetchCredentials::SameOrigin).
    pub fn with_same_origin_credentials(self) -> Self {
        Self {
            fetch_credentials: FetchCredentials::SameOrigin,
            ..self
        }
    }

    /// Return copy with [`fetch_credentials`](Self::fetch_credentials) set to
    /// [`Include`](FetchCredentials::Include).
    pub fn with_credentials(self) -> Self {
        Self {
            fetch_credentials: FetchCredentials::Include,
            ..self
        }
    }

    /// Return copy with [`fetch_credentials`](Self::fetch_credentials) set to
    /// [`Omit`](FetchCredentials::Omit).
    pub fn without_credentials(self) -> Self {
        Self {
            fetch_credentials: FetchCredentials::Omit,
            ..self
        }
    }

    /// Returns which [`BrowserFetchSettings`] have been applied to an [`http::Request`].
    pub fn from_request<B>(request: &http::Request<B>) -> Option<Self> {
        request.extensions().get().copied()
    }

    /// Applies [`BrowserFetchSettings`] to an [`http::Request`].
    ///
    /// This affects how [`compatible_service`] handles this request.
    pub fn apply_to_request<B>(self, request: &mut http::Request<B>) {
        request.extensions_mut().insert(self);
    }

    /// Adapts an [`HttpService`], applying [`BrowserFetchSettings`] to its [`http::Request`]s.
    ///
    /// [`BrowserFetchSettings`] applied to individual [`http::Request`]s take precedence over
    /// this service's [`BrowserFetchSettings`].
    pub fn adapt_service<B, S: HttpService<B>>(
        self,
        service: S,
    ) -> impl HttpService<B, Future = S::Future, ResponseBody = S::ResponseBody, Error = S::Error>
    {
        ServiceFn::http(move |mut request| {
            request.extensions_mut().get_or_insert(self);
            service.send(request)
        })
    }

    fn apply_to_request_builder(self, request_builder: RequestBuilder) -> RequestBuilder {
        let request_builder = match self.use_cors {
            true => request_builder,
            false => request_builder.fetch_mode_no_cors(),
        };
        #[cfg(target_arch = "wasm32")]
        let request_builder = match self.fetch_credentials {
            FetchCredentials::Include => request_builder.fetch_credentials_include(),
            FetchCredentials::SameOrigin => request_builder.fetch_credentials_same_origin(),
            FetchCredentials::Omit => request_builder.fetch_credentials_omit(),
        };
        request_builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::pin::pin;

    use http_body_util::{BodyExt, StreamBody};

    use super::super::util::tests::Mule;

    #[test]
    fn browser_fetch_settings_can_be_applied_to_requests() {
        for use_cors in [true, false] {
            for fetch_credentials in [
                FetchCredentials::SameOrigin,
                FetchCredentials::Include,
                FetchCredentials::Omit,
            ] {
                let settings = BrowserFetchSettings {
                    use_cors,
                    fetch_credentials,
                };
                let mut request = http::Request::new(());
                settings.apply_to_request(&mut request);
                assert_eq!(
                    BrowserFetchSettings::from_request(&request).unwrap(),
                    settings
                );
            }
        }
        let request = http::Request::new(());
        assert!(BrowserFetchSettings::from_request(&request).is_none());
    }

    #[tokio::test]
    async fn browser_fetch_settings_can_adapt_services() {
        let echo_browser_fetch_settings = ServiceFn(|request: http::Request<_>| async move {
            let browser_fetch_settings = BrowserFetchSettings::from_request(&request);
            Ok::<_, Infallible>(http::Response::new(Mule(browser_fetch_settings)))
        });
        let browser_fetch_settings = BrowserFetchSettings::default()
            .without_cors()
            .without_credentials();
        let service = browser_fetch_settings.adapt_service(echo_browser_fetch_settings);

        let mut request = http::Request::new(String::new());
        let override_settings = BrowserFetchSettings::default()
            .with_cors()
            .with_credentials();
        override_settings.apply_to_request(&mut request);
        let response = service.send(request).await.unwrap();
        assert_eq!(response.into_body().0, Some(override_settings));

        let request = http::Request::new(String::new());
        let response = service.send(request).await.unwrap();
        assert_eq!(response.into_body().0, Some(browser_fetch_settings));
    }

    #[tokio::test]
    async fn smoke_test_sized_body() {
        let chunks = ["Hello, ", "world!"];
        let frames = chunks.map(|c| Ok::<_, Infallible>(Frame::data(c.as_bytes())));
        let mut body = pin!(SizedBody {
            body: StreamBody::new(futures::stream::iter(frames)),
            remaining_size: Some(13),
        });
        assert_eq!(body.size_hint().exact(), Some(13));
        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(data, "Hello, ".as_bytes());
        assert_eq!(body.size_hint().exact(), Some(6));
        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(data, "world!".as_bytes());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.frame().await.is_none());
    }
}
