// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use http::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use http_body_util::BodyExt;
use hyper::body::Body;

use streamed_ristretto::stream::check_content_type;

use crate::service::util::BoxedError;

use super::{TryFromBody, TryIntoBody};

/// Wrapper causing contained values to be interpreted as json in requests/responses
pub struct Json<T>(pub T);

impl Json<()> {
    pub const CONTENT_TYPE: &'static str = "application/json";
}

#[derive(thiserror::Error)]
pub enum JsonDecodeError {
    #[error("Header has non-JSON content-type: {0:?}")]
    WrongContentType(Option<HeaderValue>),
    #[error("Could not read body")]
    ReadingBody(#[source] BoxedError),
    #[error("Could not decode JSON: {0}")]
    Decoding(#[source] serde_json::Error),
}

impl fmt::Debug for JsonDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WrongContentType(content_type) => f
                .debug_tuple("JsonDecodeError::WrongContentType")
                .field(content_type)
                .finish(),
            Self::ReadingBody(err) => f
                .debug_tuple("JsonDecodeError::ReadingBody")
                .field(err)
                .finish(),
            Self::Decoding(err) => f
                .debug_tuple("JsonDecodeError::Decoding")
                .field(err)
                .finish(),
        }
    }
}

impl<T: serde::Serialize> TryIntoBody for Json<T> {
    const FORMAT_NAME: &'static str = "json";

    type Body = String;
    type Error = serde_json::Error;

    fn try_into_body(self, headers: &mut HeaderMap) -> Result<Self::Body, Self::Error> {
        headers
            .entry(CONTENT_TYPE)
            .or_insert(HeaderValue::from_static(Json::CONTENT_TYPE));
        serde_json::to_string(&self.0)
    }
}

impl<B, T> TryFromBody<B> for Json<T>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxedError> + std::error::Error + Send + Sync,
    T: serde::de::DeserializeOwned,
{
    const FORMAT_NAME: &'static str = "json";

    type Error = JsonDecodeError;

    async fn try_from_body(body: B, headers: &HeaderMap) -> Result<Self, Self::Error> {
        check_content_type(headers, Json::CONTENT_TYPE)
            .map_err(|_| JsonDecodeError::WrongContentType(headers.get(CONTENT_TYPE).cloned()))?;
        let collected = body
            .collect()
            .await
            .map_err(|err| JsonDecodeError::ReadingBody(err.into()))?;
        let contents =
            serde_json::from_slice(&collected.to_bytes()).map_err(JsonDecodeError::Decoding)?;
        Ok(Self(contents))
    }
}
