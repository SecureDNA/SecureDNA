// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Utilities for working with [`HttpService`]s

use std::future::Future;

use http::header::{Entry, HeaderName, HeaderValue, InvalidHeaderValue};
use http::uri::{Scheme, Uri};
use http::{Request, Response};
use hyper::service::Service;

use shared_types::requests::RequestId;

use super::HttpService;

pub use super::dyns::{
    arced, boxed, ArcedHttpService, BoxedBody, BoxedError, BoxedHttpService, DynHttpService,
    IntoDynHttpService,
};
pub use super::outsourced::{outsourced, outsourced_with_response_capacity, OutsourcedBody};

/// Adapter from `async fn(Request) -> Result<Response, Error>` to [`Service`].
///
/// This is pretty much [`hyper::service::service_fn`], except it lacks superfluous
/// requirements for implementing non-[`HttpService`] [`Service`]s and offers
/// constructors with up-front constraints.
#[derive(Clone, Copy)]
pub struct ServiceFn<F>(pub F);

impl<F> ServiceFn<F> {
    /// Create a new [`Service`], with requirements checked up-front.
    /// This can be helpful when trying to narrow down compile errors.
    pub fn new<Req, Fut, Res, E>(f: F) -> Self
    where
        F: Fn(Req) -> Fut,
        Fut: Future<Output = Result<Res, E>>,
    {
        Self(f)
    }

    /// Create a new [`HttpService`], with requirements checked up-front.
    /// This can be helpful when trying to narrow down compile errors.
    pub fn http<ReqBody, Fut, ResBody, E>(f: F) -> Self
    where
        F: Fn(Request<ReqBody>) -> Fut,
        Fut: Future<Output = Result<Response<ResBody>, E>>,
    {
        Self(f)
    }
}

impl<F, Req, Res, Fut, E> Service<Req> for ServiceFn<F>
where
    F: Fn(Req) -> Fut,
    Fut: Future<Output = Result<Res, E>>,
{
    type Response = Res;
    type Error = E;
    type Future = Fut;

    fn call(&self, req: Req) -> Self::Future {
        (self.0)(req)
    }
}

/// Adapts `service`, converting HTTPS requests to HTTP requests.
///
/// Requests with relative URIs are unaffected.
pub fn https_to_http<B, S: HttpService<B>>(
    service: S,
) -> impl HttpService<B, Future = S::Future, ResponseBody = S::ResponseBody, Error = S::Error> {
    ServiceFn(move |mut request: Request<B>| {
        if request.uri().scheme() == Some(&Scheme::HTTPS) {
            let mut uri_parts = std::mem::take(request.uri_mut()).into_parts();
            uri_parts.scheme = Some(Scheme::HTTP);
            *request.uri_mut() = Uri::from_parts(uri_parts)
                .expect("Changing HTTPS to HTTP shouldn't invalidate a URI.");
        }
        service.send(request)
    })
}

/// Applies [`https_to_http`] to `service` if `force_http` is `true`.
///
/// This turns out to be an incredibly common use-case.
/// When `force_http` is `false`, this has no overhead compared to boxing.
pub fn force_http_if(service: impl IntoDynHttpService, force_http: bool) -> BoxedHttpService {
    if force_http {
        boxed(https_to_http(service))
    } else {
        boxed(service)
    }
}

/// Adapts `service`, adding an `x-request-id` header to all requests.
///
/// The header is only added to requests that don't have it explicitly set.
///
/// This returns an error instead of a service if the given `request_id` cannot be encoded into
/// an HTTP header.
pub fn add_request_id<B, S: HttpService<B>>(
    service: S,
    request_id: RequestId,
) -> Result<
    impl HttpService<B, Future = S::Future, ResponseBody = S::ResponseBody, Error = S::Error>,
    InvalidHeaderValue,
> {
    let x_request_id = HeaderName::from_static("x-request-id");
    let request_id = HeaderValue::from_str(&request_id.0)?;
    Ok(ServiceFn(move |mut request: Request<B>| {
        if let Entry::Vacant(entry) = request.headers_mut().entry(&x_request_id) {
            entry.insert(request_id.clone());
        }
        service.send(request)
    }))
}

/// Adapts `service`, adding a header to all requests.
///
/// The header is only added to requests that don't have it explicitly set.
pub fn add_header<B, S: HttpService<B>>(
    service: S,
    header_name: impl Into<HeaderName>,
    header_value: impl Into<HeaderValue>,
) -> impl HttpService<B, Future = S::Future, ResponseBody = S::ResponseBody, Error = S::Error> {
    let header_name = header_name.into();
    let header_value = header_value.into();
    ServiceFn(move |mut request: Request<B>| {
        if let Entry::Vacant(entry) = request.headers_mut().entry(&header_name) {
            entry.insert(header_value.clone());
        }
        service.send(request)
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use http::{Request, Response};
    use http_body_util::BodyExt;
    use hyper::body::{Body, Frame};

    // For smuggling arbitrary stuff inside body
    pub(crate) struct Mule<T>(pub T);

    impl<T> Body for Mule<T> {
        type Data = &'static [u8];
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(None)
        }
    }

    #[tokio::test]
    async fn test_https_to_http_adapter() {
        let echo_uri = ServiceFn(|request: Request<_>| async move {
            let uri = request.into_parts().0.uri;
            Ok::<_, Infallible>(Response::new(Mule(uri)))
        });

        let service = https_to_http(echo_uri);

        let send_uri = |uri| {
            let service = &service;
            async move {
                let request = Request::builder().uri(uri).body(String::new()).unwrap();
                let response = service.send(request).await.unwrap();
                response.into_body().0.to_string()
            }
        };

        assert_eq!(send_uri("https://foobar.com/").await, "http://foobar.com/");
        assert_eq!(send_uri("http://foobar.com/").await, "http://foobar.com/");
        assert_eq!(send_uri("/path").await, "/path");
    }

    #[tokio::test]
    async fn test_force_http_if_adapter() {
        let echo_uri = ServiceFn(|request: Request<_>| async move {
            let uri = request.into_parts().0.uri;
            Ok::<_, Infallible>(Response::new(uri.to_string()))
        });
        let request = Request::builder()
            .uri("https://foobar.com/")
            .body(String::new())
            .unwrap();

        let service = force_http_if(echo_uri, true);
        let response = service.send(request.clone()).await.unwrap();
        let uri = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(uri, "http://foobar.com/");

        let service = force_http_if(echo_uri, false);
        let response = service.send(request).await.unwrap();
        let uri = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(uri, "https://foobar.com/");
    }

    async fn echo_request_id<B>(
        request: Request<B>,
    ) -> Result<Response<Mule<Option<HeaderValue>>>, Infallible> {
        let request_id = request.headers().get("X-Request-ID").cloned();
        Ok(Response::new(Mule(request_id)))
    }

    #[tokio::test]
    async fn add_request_id_adds_request_id_if_missing() {
        let request_id = RequestId("xyzzy".to_owned());
        let service = add_request_id(ServiceFn(echo_request_id), request_id).unwrap();
        let request = Request::new(String::new());
        let response = service.send(request).await.unwrap();
        let request_id_header = response.into_body().0.expect("Missing request ID header");
        assert_eq!(request_id_header, "xyzzy");
    }

    #[tokio::test]
    async fn add_request_id_does_not_overwrite_header() {
        let request_id = RequestId("xyzzy".to_owned());
        let service = add_request_id(ServiceFn(echo_request_id), request_id).unwrap();
        let request = Request::builder()
            .header("X-Request-Id", "foo")
            .body(String::new())
            .unwrap();
        let response = service.send(request).await.unwrap();
        let request_id_header = response.into_body().0.expect("Missing request ID header");
        assert_eq!(request_id_header, "foo");
    }

    #[tokio::test]
    async fn add_request_id_rejects_unsendable_id() {
        // Ugh... https://github.com/hyperium/http/issues/519
        // I guess octo🐙id won't be a feasible test case.
        let request_id = RequestId("delete\x7fchar".to_owned());
        let service = add_request_id(ServiceFn(echo_request_id::<String>), request_id);
        assert!(service.is_err());
    }

    #[tokio::test]
    async fn add_header_adds_header_if_missing() {
        let header = HeaderName::from_static("x-request-id");
        let service = add_header(ServiceFn(echo_request_id), header, 123);
        let request = Request::new(String::new());
        let response = service.send(request).await.unwrap();
        let request_id_header = response.into_body().0.expect("Missing request ID header");
        assert_eq!(request_id_header, "123");
    }

    #[tokio::test]
    async fn add_header_does_not_overwrite_header() {
        let header = HeaderName::from_static("x-request-id");
        let service = add_header(ServiceFn(echo_request_id), header, 123);
        let request = Request::builder()
            .header("X-Request-Id", "foo")
            .body(String::new())
            .unwrap();
        let response = service.send(request).await.unwrap();
        let request_id_header = response.into_body().0.expect("Missing request ID header");
        assert_eq!(request_id_header, "foo");
    }
}
