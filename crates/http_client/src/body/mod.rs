// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::Infallible;
use std::future::Future;

use bytes::Bytes;
use http::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use http::{Request, Response};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Body;

use streamed_ristretto::stream::check_content_type;

use crate::service::util::BoxedError;

pub mod json;
pub mod zerocopy;

// Common enough it should probably be accessible from here...
pub use self::json::Json;

/// Allows a type to be converted into something implementing [`Body`].
pub trait TryIntoBody {
    /// A (usually human-readable) name for this content type.
    const FORMAT_NAME: &'static str;

    /// The [`Body`] this can be converted into.
    type Body: Body;
    /// The error returned if conversion fails.
    type Error;

    /// Attempt to convert this type into a body and populate necessary headers.
    ///
    /// `headers` is the list of headers in the [`Request`] or [`Response`]. It should at least
    /// be populated with a `Content-Type` if one doesn't already exist. Other headers may be set
    /// if necessary. Generally, `Content-Length` doesn't need to be set because that can be
    /// inferred from exact [`Body::size_hint`]s.
    fn try_into_body(self, headers: &mut HeaderMap) -> Result<Self::Body, Self::Error>;

    /// Convenience method for overriding a [`CONTENT_TYPE`].
    fn with_content_type(self, content_type: &'static str) -> WithContentType<Self>
    where
        Self: Sized,
    {
        WithContentType::new(self, HeaderValue::from_static(content_type))
    }

    /// Convert this into a [`Request`].
    fn try_into_request(self) -> Result<Request<Self::Body>, Self::Error>
    where
        Self: Sized,
    {
        let mut headers = HeaderMap::new();
        let body = self.try_into_body(&mut headers)?;
        let mut request = Request::new(body);
        *request.headers_mut() = headers;
        Ok(request)
    }

    /// Convert this into a [`Response`].
    fn try_into_response(self) -> Result<Response<Self::Body>, Self::Error>
    where
        Self: Sized,
    {
        let mut headers = HeaderMap::new();
        let body = self.try_into_body(&mut headers)?;
        let mut response = Response::new(body);
        *response.headers_mut() = headers;
        Ok(response)
    }
}

/// Allows a type to be converted from [`Body`]s.
pub trait TryFromBody<B: Send + 'static>: Sized {
    /// A (usually human-readable) name for this content type.
    const FORMAT_NAME: &'static str;

    /// The error returned if conversion fails.
    type Error;

    /// Attempt to build this type from a body and request/response headers.
    ///
    /// This should check the `Content-Type`.
    fn try_from_body(
        body: B,
        headers: &HeaderMap,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}

/// Provide no [`Body`].
impl TryIntoBody for () {
    const FORMAT_NAME: &'static str = "no body";

    type Body = Empty<Bytes>;
    type Error = Infallible;

    fn try_into_body(self, _headers: &mut HeaderMap) -> Result<Self::Body, Self::Error> {
        Ok(Empty::new())
    }
}

// Not sure whether to have this expect "no body" or allow "any body".
// Symmetry suggests "no body", but I imagine "any body" may be better for ergonomics and
// backwards compat, and maybe even the principle of least surprise?
/// Accept any [`Body`].
impl<B: Send + 'static> TryFromBody<B> for () {
    const FORMAT_NAME: &'static str = "ignored body";

    type Error = Infallible;

    async fn try_from_body(_body: B, _headers: &HeaderMap) -> Result<Self, Self::Error> {
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum PlaintextDecodeError {
    #[error("Header has non-plaintext content-type: {0:?}")]
    WrongContentType(Option<HeaderValue>),
    #[error("Could not read body")]
    ReadingBody(#[source] BoxedError),
    #[error("Could not decode plaintext: {0}")]
    Decoding(#[source] std::string::FromUtf8Error),
}

/// Provide text.
impl TryIntoBody for String {
    const FORMAT_NAME: &'static str = "plaintext";

    type Body = String;
    type Error = Infallible;

    fn try_into_body(self, headers: &mut HeaderMap) -> Result<Self::Body, Self::Error> {
        headers
            .entry(CONTENT_TYPE)
            .or_insert(HeaderValue::from_static("text/plain;charset=UTF-8"));
        Ok(self)
    }
}

/// Accept text. (currently only UTF-8)
///
/// Curently a hacky, minimal implementation. (doesn't properly handle content-types)
impl<B> TryFromBody<B> for String
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync,
{
    const FORMAT_NAME: &'static str = "plaintext";

    type Error = PlaintextDecodeError;

    async fn try_from_body(body: B, headers: &HeaderMap) -> Result<Self, Self::Error> {
        // TODO: ideally, this wouldn't be case sensitive and would handle multiple charsets
        check_content_type(headers, "text/plain;charset=UTF-8").map_err(|_| {
            PlaintextDecodeError::WrongContentType(headers.get(CONTENT_TYPE).cloned())
        })?;
        let data = body
            .collect()
            .await
            .map_err(|err| PlaintextDecodeError::ReadingBody(err.into()))?
            .to_bytes()
            .to_vec();
        String::from_utf8(data).map_err(PlaintextDecodeError::Decoding)
    }
}

/// Provide bytes of no particular content-type.
///
/// You'll need to set the [`CONTENT_TYPE`] header yourself.
impl TryIntoBody for Bytes {
    const FORMAT_NAME: &'static str = "binary";

    type Body = Full<Bytes>;
    type Error = Infallible;

    fn try_into_body(self, _headers: &mut HeaderMap) -> Result<Self::Body, Self::Error> {
        Ok(self.into())
    }
}

/// Accept bytes of any content-type.
impl<B> TryFromBody<B> for Bytes
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync,
{
    const FORMAT_NAME: &'static str = "binary";

    type Error = BoxedError;

    async fn try_from_body(body: B, _headers: &HeaderMap) -> Result<Self, Self::Error> {
        Ok(body.collect().await?.to_bytes())
    }
}

/// Provides a body with an overridden [`CONTENT_TYPE`].
pub struct WithContentType<T> {
    inner: T,
    content_type: HeaderValue,
}

impl<T> WithContentType<T> {
    pub fn new(inner: T, content_type: impl Into<HeaderValue>) -> Self {
        Self {
            inner,
            content_type: content_type.into(),
        }
    }
}

impl<T: TryIntoBody> TryIntoBody for WithContentType<T> {
    const FORMAT_NAME: &'static str = T::FORMAT_NAME;

    type Body = T::Body;
    type Error = T::Error;

    fn try_into_body(self, headers: &mut HeaderMap) -> Result<Self::Body, Self::Error> {
        headers.entry(CONTENT_TYPE).or_insert(self.content_type);
        self.inner.try_into_body(headers)
    }
}

pub struct WithHeaders<T> {
    pub inner: T,
    pub headers: HeaderMap,
}

impl<T, B> TryFromBody<B> for WithHeaders<T>
where
    T: TryFromBody<B>,
    B: Send + 'static,
{
    const FORMAT_NAME: &'static str = T::FORMAT_NAME;

    type Error = T::Error;

    async fn try_from_body(body: B, headers: &HeaderMap) -> Result<Self, Self::Error> {
        let inner = T::try_from_body(body, headers).await?;
        Ok(Self {
            inner,
            headers: headers.clone(),
        })
    }
}
