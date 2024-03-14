// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Context;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{body::Body, header::HeaderValue, HeaderMap, Request};

use scep::{cookie::SessionCookie, error::ScepError};

/// Do the SCEP pre-parsing checks on the body:
/// * Has Content-Length
/// * Content-Length < size_limit
/// * First non-ASCII-whitespace character is '{'
/// And return either the body `Bytes` or the appropriate `SCEPError`.
pub async fn check_and_extract_json_body<B, E>(
    size_limit: u64,
    request: Request<B>,
) -> Result<Bytes, ScepError<E>>
where
    B: Body,
    B::Error: std::error::Error + Send + Sync + 'static,
    E: std::error::Error,
{
    let body = match request.body().size_hint().exact() {
        Some(size) if size <= size_limit => request
            .into_body()
            .collect()
            .await
            .context("while reading body")
            .map_err(ScepError::InternalError)?
            .to_bytes(),
        Some(size) => {
            return Err(ScepError::InvalidMessage(anyhow::anyhow!(
                "request too large ({size}b), maximum {size_limit}b"
            )))
        }
        None => {
            return Err(ScepError::InvalidMessage(anyhow::anyhow!(
                "request must have a fixed Content-Length, chunked encoding not supported"
            )))
        }
    };

    let first_non_ws = body.iter().find(|c| !c.is_ascii_whitespace());
    match first_non_ws {
        Some(b'{') => Ok(body),
        _ => Err(ScepError::BadProtocol),
    }
}

/// Parse a JSON request from bytes, returning either a `serde_json::Value` or
/// `SCEPError::InvalidMessage`
pub fn parse_json_body<E>(body: impl AsRef<[u8]>) -> Result<serde_json::Value, ScepError<E>>
where
    E: std::error::Error,
{
    serde_json::from_slice(body.as_ref())
        .context("while parsing body json")
        .map_err(ScepError::InvalidMessage)
}

/// Try to get the SCEP session cookie, returning `ScepError::InvalidMessage` if
/// there are none, multiple, or the format is incorrect.
pub fn get_session_cookie<E>(
    headers: &HeaderMap<HeaderValue>,
) -> Result<SessionCookie, ScepError<E>>
where
    E: std::error::Error,
{
    let mut cookies = headers
        .get_all(hyper::header::COOKIE)
        .into_iter()
        .filter_map(|cookie| {
            let cookie = cookie.to_str().ok()?;
            let cookie = cookie::Cookie::parse(cookie).ok()?;
            let cookie: SessionCookie = cookie.value().parse().ok()?;
            Some(cookie)
        });

    let cookie = cookies.next().ok_or_else(|| {
        ScepError::InvalidMessage(anyhow::anyhow!("missing or invalid session cookie"))
    })?;

    if cookies.next().is_some() {
        Err(ScepError::InvalidMessage(anyhow::anyhow!(
            "multiple valid session cookies"
        )))
    } else {
        Ok(cookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn too_long_body_rejected() {
        let (size, limit) = (128, 100);
        let request = Request::builder().body("a".repeat(size).boxed()).unwrap();
        assert!(matches!(
            check_and_extract_json_body::<_, scep::error::ServerPrevalidation>(limit, request)
                .await
                .unwrap_err(),
            ScepError::InvalidMessage(_)
        ));
    }
}
