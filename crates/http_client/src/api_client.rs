// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
#[cfg(not(target_arch = "wasm32"))]
use futures::FutureExt;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, Uri};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};

use packed_ristretto::{PackableRistretto, PackedRistrettos};
#[cfg(not(target_arch = "wasm32"))]
use shared_types::requests::RequestId;
use streamed_ristretto::HasContentType;
use streamed_ristretto::stream::{check_content_length, check_content_type};

use crate::body::{TryFromBody, TryIntoBody};
use crate::error::HttpError;
#[cfg(not(target_arch = "wasm32"))]
use crate::error::UnusableRequestId;
use crate::service::HttpService;
use crate::service::util::{ArcedHttpService, BoxedBody, BoxedError, IntoDynHttpService, arced};
use crate::status_code::is_retriable;

/// Helper for querying internal servers (HDB and keyservers)
#[derive(Clone)]
pub struct BaseApiClient {
    service: ArcedHttpService,
}

impl<S: IntoDynHttpService> From<S> for BaseApiClient {
    /// Construct a new [`BaseApiClient`] from an [`HttpService`].
    ///
    /// The given service is used directly, so it's responsible for any request IDs, etc.
    fn from(service: S) -> Self {
        Self {
            service: arced(service),
        }
    }
}

// constructors for the usual case where we're using ApiClientCoreImpl
impl BaseApiClient {
    /// Construct a new ApiClient for the given RequestId. It will attach this
    /// id to each request it makes.
    ///
    /// This isn't available on WASM because http-related types on WASM aren't
    /// [`Send`]able between threads, so they'll need to be isolated to a worker;
    /// use [`service_and_worker`](crate::service_and_worker) instead.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(request_id: RequestId) -> Result<Self, UnusableRequestId> {
        let (service, worker) = crate::securedna_service_and_worker(request_id)?;
        // Outside of WASM32, service_and_worker should return a no-op worker.
        assert_eq!(worker.now_or_never(), Some(()));
        Ok(service.into())
    }

    /// Construct a new ApiClient for use with external APIs: it won't set any headers
    /// or handle API keys.
    ///
    /// This isn't available on WASM because http-related types on WASM aren't
    /// [`Send`]able between threads, so they'll need to be isolated to a worker;
    /// use [`service_and_worker`](crate::service_and_worker) instead.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_external() -> Self {
        let (service, worker) = crate::service_and_worker();
        // Outside of WASM32, service_and_worker should return a no-op worker.
        assert_eq!(worker.now_or_never(), Some(()));
        service.into()
    }

    /// Post ristrettos, get JSON. Returns error for >=400 status.
    pub async fn ristretto_json_post<I, O>(
        &self,
        url: &str,
        packed_ristrettos: &PackedRistrettos<I>,
    ) -> Result<O, HttpError>
    where
        I: PackableRistretto + HasContentType,
        O: serde::de::DeserializeOwned,
        for<'a> &'a I::Array: IntoIterator<Item = &'a u8>,
    {
        let body: Vec<_> = packed_ristrettos
            .iter_encoded()
            .flatten()
            .copied()
            .collect();
        let bytes = self
            .raw_post(
                url,
                body.into(),
                I::CONTENT_TYPE,
                &[],
                Some("application/json"),
            )
            .await?;

        serde_json::from_slice(&bytes).map_err(|e| {
            let error_text = format_serde_error_from_bytes(bytes.into(), e);
            HttpError::DecodeError {
                decoding: format!("json from {url}"),
                source: error_text.into(),
            }
        })
    }

    /// Post ristrettos, get ristrettos. Returns error for >=400 status.
    #[allow(dead_code)]
    pub async fn ristretto_ristretto_post<I, O>(
        &self,
        url: &str,
        packed_ristrettos: &PackedRistrettos<I>,
    ) -> Result<PackedRistrettos<O>, HttpError>
    where
        I: PackableRistretto + HasContentType,
        O: PackableRistretto + HasContentType + 'static,
        for<'a> &'a I::Array: IntoIterator<Item = &'a u8>,
    {
        self.ristretto_ristretto_post_with_headers(url, packed_ristrettos, &[])
            .await
    }

    /// Post ristrettos, get ristrettos (with custom headers). Returns error for >=400 status.
    pub async fn ristretto_ristretto_post_with_headers<I, O>(
        &self,
        url: &str,
        packed_ristrettos: &PackedRistrettos<I>,
        headers: &[(String, String)],
    ) -> Result<PackedRistrettos<O>, HttpError>
    where
        I: PackableRistretto + HasContentType,
        O: PackableRistretto + HasContentType + 'static,
        for<'a> &'a I::Array: IntoIterator<Item = &'a u8>,
    {
        let body: Vec<_> = packed_ristrettos
            .iter_encoded()
            .flatten()
            .copied()
            .collect();

        let bytes = self
            .raw_post(
                url,
                body.into(),
                I::CONTENT_TYPE,
                headers,
                Some(O::CONTENT_TYPE),
            )
            .await?;

        let content_len = bytes.len().try_into().ok();
        check_content_length(content_len, O::SIZE).map_err(|e| HttpError::DecodeError {
            decoding: format!("decoding ristretto points from {url}"),
            source: e.into(),
        })?;

        let packed_ristrettos = bytes
            .chunks_exact(O::SIZE)
            .map(|c| <O::Array>::try_from(c).ok().unwrap())
            .collect();
        Ok(packed_ristrettos)
    }
    /// Post bytes, get bytes. Bring your own content-type. Returns error for >=400 status.
    pub async fn bytes_bytes_post(
        &self,
        url: &str,
        body: Bytes,
        content_type: &'static str,
        expected_content_type: Option<&'static str>,
    ) -> Result<Bytes, HttpError> {
        self.raw_post(url, body, content_type, &[], expected_content_type)
            .await
    }

    /// Post bytes, get JSON. Bring your own content-type. Returns error for >=400 status.
    pub async fn bytes_json_post_with_headers<O: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: Bytes,
        content_type: &'static str,
        headers: &[(String, String)],
    ) -> Result<O, HttpError> {
        let bytes = self
            .raw_post(url, body, content_type, headers, None)
            .await?;

        serde_json::from_slice(&bytes).map_err(|e| {
            let error_text = format_serde_error_from_bytes(bytes.into(), e);
            HttpError::DecodeError {
                decoding: format!("json from {url}"),
                source: error_text.into(),
            }
        })
    }

    /// Post bytes, get JSON. Bring your own content-type. Returns error for >=400 status.
    pub async fn bytes_json_post<O: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: Bytes,
        content_type: &'static str,
    ) -> Result<O, HttpError> {
        self.bytes_json_post_with_headers(url, body, content_type, &[])
            .await
    }

    pub async fn raw_post(
        &self,
        url: &str,
        body: Bytes,
        content_type: &'static str,
        header_iter: &[(String, String)],
        expected_content_type: Option<&'static str>,
    ) -> Result<bytes::Bytes, HttpError> {
        raw_request_to_service(
            &self.service,
            url,
            Some(body),
            content_type,
            header_iter,
            expected_content_type,
        )
        .await
    }

    /// Convenience API for [`GET`](Method::GET) requests.
    ///
    /// See [`request`](Self::request) for details.
    pub async fn get<U, T>(&self, uri: U) -> Result<T, HttpError>
    where
        U: TryInto<Uri, Error: Into<http::Error> + fmt::Debug>,
        T: TryFromBody<HttpBody, Error: Into<BoxedError>>,
    {
        let uri = uri.try_into().map_err(|err| HttpError::RequestError {
            ctx: format!("invalid uri; {err:?}"),
            status: None,
            retriable: true,
            source: err.into().into(),
        })?;

        // Avoiding builder so this is infallible.
        let mut request = Request::new(());
        *request.uri_mut() = uri;

        let response = self.request(request).await?;
        Ok(response.into_body())
    }

    /// Convenience API for [`POST`](Method::POST) requests.
    ///
    /// See [`request`](Self::request) for details.
    pub async fn post<U, S, T>(&self, uri: U, request_body: S) -> Result<T, HttpError>
    where
        U: TryInto<Uri, Error: Into<http::Error> + fmt::Debug>,
        S: TryIntoBody<Body: Send + 'static, Error: Into<BoxedError>>,
        <S::Body as Body>::Error: Into<BoxedError>,
        T: TryFromBody<HttpBody, Error: Into<BoxedError>>,
    {
        let uri = uri.try_into().map_err(|err| HttpError::RequestError {
            ctx: format!("invalid uri; {err:?}"),
            status: None,
            retriable: true,
            source: err.into().into(),
        })?;

        // Avoiding builder so this is infallible.
        let mut request = Request::new(request_body);
        *request.method_mut() = Method::POST;
        *request.uri_mut() = uri;

        let response = self.request(request).await?;
        Ok(response.into_body())
    }

    /// General-ish request API that produces errors the rest of the codebase expects.
    ///
    /// Note that **this returns an error if the status code indicates a failure**.
    /// If that happens, the entire request will be pre-emptively downloaded.
    pub fn request<S, T>(
        &self,
        request: Request<S>,
        // NOTE: Explicit Send impl on Future is necessary to work around trait solver limitations.
    ) -> impl Future<Output = Result<Response<T>, HttpError>> + Send + use<S, T>
    where
        S: TryIntoBody<Body: Send + 'static, Error: Into<BoxedError>>,
        <S::Body as Body>::Error: Into<BoxedError>,
        T: TryFromBody<HttpBody, Error: Into<BoxedError>>,
    {
        // Doing this up-front so we don't need `S: Send` for the async block to be `Send`.
        let (mut parts, body) = request.into_parts();
        let request = match body.try_into_body(&mut parts.headers) {
            Ok(body) => Ok(Request::from_parts(parts, body)),
            Err(err) => Err(HttpError::EncodeError {
                encoding: format!("{} to {:?}", S::FORMAT_NAME, &parts.uri),
                source: err.into(),
            }),
        };

        let this = self.clone();
        async move {
            let request = request?;
            let uri = request.uri().clone();

            let response =
                this.service
                    .send(request)
                    .await
                    .map_err(|source| HttpError::RequestError {
                        ctx: format!("requesting {uri:?}"),
                        status: None,
                        retriable: true,
                        source,
                    })?;
            let status = response.status();
            let retriable = is_retriable(status.as_u16());
            let response = response.map(|body| HttpBody {
                inner: body,
                ctx: format!("receiving body from {uri:?}"),
                status: Some(status.as_u16()),
                retriable,
            });

            if status.is_client_error() || status.is_server_error() {
                // Download whole body for backwards compat with existing code.
                // It's a shame that prevents the client from cutting the connection early.
                let body = response.into_body().collect().await?.to_bytes();
                return Err(HttpError::RequestError {
                    ctx: format!("requesting {uri:?}"),
                    status: Some(status.as_u16()),
                    retriable,
                    source: String::from_utf8_lossy(&body).into(),
                });
            }

            let (parts, body) = response.into_parts();
            let body = T::try_from_body(body, &parts.headers)
                .await
                .map_err(|err| HttpError::DecodeError {
                    decoding: format!("{} from {uri:?}", T::FORMAT_NAME),
                    source: err.into(),
                })?;
            Ok(Response::from_parts(parts, body))
        }
    }

    /// Low-level HTTP API. You'll need [`HttpService`] to use this.
    pub fn service(&self) -> &ArcedHttpService {
        &self.service
    }
}

impl fmt::Debug for BaseApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseApiClient").finish_non_exhaustive()
    }
}

fn format_serde_error_from_bytes(
    bytes: Vec<u8>,
    e: impl Into<format_serde_error::ErrorTypes>,
) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => format_serde_error::SerdeError::new(text, e).to_string(),
        Err(err) => err.to_string(),
    }
}

async fn raw_request_to_service<S>(
    service: S,
    url: &str,
    body: Option<Bytes>,
    content_type: &'static str,
    headers: &[(String, String)],
    expected_content_type: Option<&'static str>,
) -> Result<bytes::Bytes, HttpError>
where
    S: HttpService<http_body_util::Full<Bytes>> + Sync,
    S::Future: Send,
    S::ResponseBody: Body + Send,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Into<BoxedError>,
    S::Error: Into<BoxedError>,
{
    let method = if body.is_some() {
        Method::POST
    } else {
        Method::GET
    };
    let mut request_builder = Request::builder().method(method).uri(url);
    if body.is_some() {
        request_builder = request_builder.header(CONTENT_TYPE, content_type);
    }
    for (k, v) in headers {
        request_builder = request_builder.header(k, v);
    }
    let body = http_body_util::Full::new(body.unwrap_or_default());
    let request = request_builder
        .body(body)
        .map_err(|e| HttpError::RequestError {
            ctx: format!("building request for {url}"),
            status: None,
            retriable: true,
            source: e.into(),
        })?;
    let response = service
        .send(request)
        .await
        .map_err(|e| HttpError::RequestError {
            ctx: format!("requesting {url}"),
            status: None,
            retriable: true,
            source: e.into(),
        })?;

    let status = response.status();
    let retriable = is_retriable(response.status().as_u16());
    let (parts, body) = response.into_parts();

    let body = body
        .collect()
        .await
        .map_err(|e| HttpError::RequestError {
            ctx: format!("requesting {url}"),
            status: Some(status.as_u16()),
            retriable,
            source: e.into(),
        })?
        .to_bytes();

    if status.is_client_error() || status.is_server_error() {
        return Err(HttpError::RequestError {
            ctx: format!("requesting {url}"),
            status: Some(status.as_u16()),
            retriable,
            source: String::from_utf8_lossy(&body).into(),
        });
    }
    if let Some(content_type) = expected_content_type
        && let Err(err) = check_content_type(&parts.headers, content_type)
    {
        return Err(HttpError::RequestError {
            ctx: format!("requesting {url}"),
            status: Some(status.as_u16()),
            retriable,
            source: format!("{}: {}", err, String::from_utf8_lossy(&body)).into(),
        });
    }
    Ok(body)
}

/// A [`Body`] whose errors are [`HttpError`]s.
///
/// This is essentially a concrete type for `boxed_body.map_err(|err| HttpError {...})`.
#[pin_project::pin_project]
pub struct HttpBody {
    #[pin]
    inner: BoxedBody,
    // For populating errors
    ctx: String,
    status: Option<u16>,
    retriable: bool,
}

impl Body for HttpBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        this.inner
            .poll_frame(cx)
            .map_err(|err| HttpError::RequestError {
                ctx: this.ctx.clone(),
                status: *this.status,
                retriable: *this.retriable,
                source: err,
            })
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;

    use http::{HeaderMap, Response};

    use crate::service::util::ServiceFn;

    #[tokio::test]
    async fn sanity_check_get_request() {
        let service = ServiceFn::http(|request| async move {
            assert_eq!(request.method(), Method::GET);
            let status = match request.uri().path() {
                "/success" => 200,
                _ => 404,
            };

            let response = Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "text/plain")
                .body(request.uri().to_string())
                .unwrap();
            Ok::<_, Infallible>(response)
        });
        let client = BaseApiClient::from(service);

        let () = client.get("/success").await.unwrap();

        let err = client.get::<_, ()>("/missing").await.unwrap_err();
        match err {
            HttpError::RequestError {
                ctx,
                status,
                retriable,
                source,
            } => {
                assert_eq!(ctx, "requesting /missing");
                assert_eq!(status, Some(404));
                assert!(!retriable);
                assert_eq!(source.to_string(), "/missing".to_owned());
            }
            err => panic!("not a RequestError: {err:?}"),
        }
    }

    #[tokio::test]
    async fn sanity_check_post_request() {
        let service = ServiceFn::http(|request| async move {
            assert_eq!(request.method(), Method::POST);
            let status = match request.uri().path() {
                "/success" => 200,
                _ => 404,
            };

            let response = Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "text/plain;charset=UTF-8")
                .body(request.into_body())
                .unwrap();
            Ok::<_, Infallible>(response)
        });
        let client = BaseApiClient::from(service);

        let output: String = client
            .post("/success", "some content".to_string())
            .await
            .unwrap();
        assert_eq!(output, "some content");

        let err = client
            .post::<_, _, String>("/missing", "some content".to_string())
            .await
            .unwrap_err();
        match err {
            HttpError::RequestError {
                ctx,
                status,
                retriable,
                source,
            } => {
                assert_eq!(ctx, "requesting /missing");
                assert_eq!(status, Some(404));
                assert!(!retriable);
                assert_eq!(source.to_string(), "some content".to_owned());
            }
            err => panic!("not a RequestError: {err:?}"),
        }
    }

    #[tokio::test]
    async fn regression_test_that_request_method_propagates_size_hints() {
        struct ExtractBody<T>(T);

        impl<B: Send + 'static> TryFromBody<B> for ExtractBody<B> {
            const FORMAT_NAME: &'static str = "body";

            type Error = Infallible;

            async fn try_from_body(body: B, _: &HeaderMap) -> Result<Self, Self::Error> {
                Ok(Self(body))
            }
        }

        let echo_service = ServiceFn::http(|request| async {
            let response = Response::builder().body(request.into_body()).unwrap();
            Ok::<_, Infallible>(response)
        });
        let api_client = BaseApiClient::from(echo_service);

        let ExtractBody(body) = api_client
            .post("/foo", "This string has 30 characters.".to_owned())
            .await
            .unwrap();
        assert_eq!(body.size_hint().exact(), Some(30));
    }

    #[test]
    fn methods_can_be_send() {
        fn assert_send(_: &impl Send) {}

        let service = ServiceFn::http(|request| async move {
            Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .body(request.into_body())
        });
        let client = BaseApiClient::from(service);

        let future = client.request::<_, String>(Request::new(String::new()));
        assert_send(&future);
        let future = client.get::<_, String>("/url");
        assert_send(&future);
        let future = client.post::<_, _, String>("/url", String::new());
        assert_send(&future);
    }

    #[tokio::test]
    async fn request_uri_is_passed() {
        let service = ServiceFn::http(|request| async move {
            let response = Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .body(request.uri().to_string())
                .unwrap();
            Ok::<_, Infallible>(response)
        });

        let response = raw_request_to_service(
            service,
            "/this/is/a/path",
            None,
            "",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap();
        assert_eq!(*response, *b"/this/is/a/path");
    }

    #[tokio::test]
    async fn request_method_depends_on_body() {
        let service = ServiceFn::http(|request| async move {
            let response = Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .body(request.method().to_string())
                .unwrap();
            Ok::<_, Infallible>(response)
        });

        let response = raw_request_to_service(&service, "/", None, "", &[], Some("text/plain"))
            .await
            .unwrap();
        assert_eq!(*response, *b"GET");

        let response =
            raw_request_to_service(&service, "/", Some("".into()), "", &[], Some("text/plain"))
                .await
                .unwrap();
        assert_eq!(*response, *b"POST");
    }

    #[tokio::test]
    async fn content_type_depends_on_body() {
        let service = ServiceFn::http(|request| async move {
            let body = match request.headers().get(CONTENT_TYPE) {
                Some(content_type) => content_type.to_str().unwrap().to_string(),
                None => "(no content type)".to_owned(),
            };
            let response = Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .body(body)
                .unwrap();
            Ok::<_, Infallible>(response)
        });

        let response = raw_request_to_service(
            &service,
            "/",
            None,
            "contenttype/foobar",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap();
        assert_eq!(*response, *b"(no content type)");

        let response = raw_request_to_service(
            &service,
            "/",
            Some("".into()),
            "contenttype/foobar",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap();
        assert_eq!(*response, *b"contenttype/foobar");
    }

    #[tokio::test]
    async fn request_body_is_passed() {
        let service = ServiceFn::http(|request| async move {
            let response = Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .body(request.into_body())
                .unwrap();
            Ok::<_, Infallible>(response)
        });

        let response = raw_request_to_service(
            service,
            "/",
            Some("This is a body.".into()),
            "text/plain",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap();
        assert_eq!(*response, *b"This is a body.");
    }

    #[tokio::test]
    async fn request_headers_are_passed() {
        let service = ServiceFn::http(|request| async move {
            let mut headers: Vec<_> = request
                .headers()
                .iter()
                .map(|(k, v)| format!("{} = {}", k.as_str(), v.to_str().unwrap()))
                .collect();
            headers.sort();
            let body = headers.join("\n");
            let response = Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .body(body)
                .unwrap();
            Ok::<_, Infallible>(response)
        });

        let headers = &[
            ("header1".to_owned(), "value1".to_owned()),
            ("header2".to_owned(), "value2".to_owned()),
            ("header3".to_owned(), "value3".to_owned()),
        ];
        let response = raw_request_to_service(service, "/", None, "", headers, Some("text/plain"))
            .await
            .unwrap();
        assert_eq!(
            *response,
            *b"header1 = value1\nheader2 = value2\nheader3 = value3"
        );
    }

    #[tokio::test]
    async fn rejects_unexpected_content_types() {
        let service = ServiceFn(|_| async move {
            let response = Response::builder()
                .header(CONTENT_TYPE, "text/nonsense")
                .body("Jabberwocky".to_owned())
                .unwrap();
            Ok::<_, Infallible>(response)
        });

        let err = raw_request_to_service(&service, "/", None, "", &[], Some("text/plain"))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::RequestError { .. }));

        let response = raw_request_to_service(&service, "/", None, "", &[], Some("text/nonsense"))
            .await
            .unwrap();
        assert_eq!(*response, *b"Jabberwocky");
    }

    #[tokio::test]
    async fn rejects_bad_statuses() {
        let respond_with_status = |status| {
            ServiceFn(move |_| async move {
                let response = Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(String::new())
                    .unwrap();
                Ok::<_, Infallible>(response)
            })
        };

        raw_request_to_service(
            respond_with_status(200),
            "/",
            None,
            "",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap();
        raw_request_to_service(
            respond_with_status(303),
            "/",
            None,
            "",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap();
        raw_request_to_service(
            respond_with_status(400),
            "/",
            None,
            "",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap_err();
        raw_request_to_service(
            respond_with_status(500),
            "/",
            None,
            "",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap_err();
    }

    #[tokio::test]
    async fn uses_bodies_with_size_hints() {
        let service = ServiceFn::http(|request| async move {
            // Ugh... can't use .size_hint() because it mysteriously breaks type inference
            let size_hint = Body::size_hint(request.body());
            let body = size_hint.exact().unwrap().to_string();
            let response = Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .body(body)
                .unwrap();
            Ok::<_, Infallible>(response)
        });

        let response = raw_request_to_service(
            service,
            "/",
            Some("This is a body.".into()),
            "text/plain",
            &[],
            Some("text/plain"),
        )
        .await
        .unwrap();
        assert_eq!(*response, *b"15");
    }
}
