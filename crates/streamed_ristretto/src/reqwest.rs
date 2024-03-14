// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tools for implementing [`reqwest`] clients

use std::any::Any;
use std::borrow::Cow;
use std::io::Cursor;

use futures::{Stream, TryStream, TryStreamExt};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Body, RequestBuilder, Response};

use crate::contenttype::HasContentType;
pub use crate::stream::{
    check_content_length, HasShortErrorMsg, MessageError, RistrettoError, StreamableRistretto,
    HASH_SIZE,
};
use crate::stream::{decode, ConversionError};
use crate::util;

/// Add fallible stream of ristrettos to the body of a [`RequestBuilder`]
///
/// This will appropriately set the `Content-Type`, and the body will buffer up
/// about 256KB worth of data before producing a frame.
pub fn add_ristrettos<S>(mut request_builder: RequestBuilder, ristrettos: S) -> RequestBuilder
where
    S: TryStream + Send + Sync + 'static,
    S::Ok: HasContentType + Into<[u8; HASH_SIZE]>,
    S::Error: std::error::Error + Send + Sync,
{
    request_builder = request_builder.header(CONTENT_TYPE, S::Ok::CONTENT_TYPE);

    let buffer_size = 256 * 1024;
    let body = util::buffered(ristrettos.map_ok(|r| Cursor::new(r.into())), buffer_size);
    request_builder.body(Body::wrap_stream(body))
}

/// Convert a [`Response`] into a fallible stream of `R`
///
/// Note that this checks that `Content-Type` matches
/// [`R::CONTENT_TYPE`](HasContentType::CONTENT_TYPE), but does not check the `Content-Length`;
/// see [`check_content_length`] for that.
pub fn from_response<R: StreamableRistretto>(
    response: Response,
) -> Result<
    impl Stream<Item = Result<R, RistrettoError<reqwest::Error, ConversionError<R>>>>,
    MessageError,
> {
    check_content_type(response.headers(), R::CONTENT_TYPE)?;
    Ok(decode::<_, R>(response.bytes_stream()))
}

/// Checks that the given header map has the expected content-type
///
/// If no `Content-Type` is provided, a default of `application/octet-stream` is assumed, per
/// [RFC 9110 section 8.3](https://httpwg.org/specs/rfc9110.html#rfc.section.8.3).
///
/// Currently returns an error if any `Content-Type` header is wrong. This needs to
/// be fixed to have proper HTTP semantics (case insensitivity, treating multiple
/// headers as joined by commas, etc).
pub fn check_content_type(
    headers: &reqwest::header::HeaderMap,
    expected: &'static str,
) -> Result<(), MessageError> {
    // Note: We assume check_content_type only pays attention to the CONTENT_TYPE header.
    let headers = convert_content_type_headers(headers);
    crate::stream::check_content_type(&headers, expected)
}

/// Provides a `hyper`-compatible copy of content-type headers
///
/// If possible, it avoids copying and just passes the reference through unchanged.
fn convert_content_type_headers(headers: &reqwest::header::HeaderMap) -> Cow<http::HeaderMap> {
    if let Some(headers) = (headers as &dyn Any).downcast_ref::<http::HeaderMap>() {
        // Should optimize down to no-op whenever hyper and reqwest use the same version of http...
        Cow::Borrowed(headers)
    } else {
        // If worse comes to worse, we fall back to copying as necessary,
        // but hopefully HTTP requests will be uncommon enough not to matter.
        let headers = headers
            .get_all(CONTENT_TYPE)
            .into_iter()
            .flat_map(|content_type| {
                // Not actually expecting the conversions to ever fail.
                http::header::HeaderValue::from_bytes(content_type.as_ref()).ok()
            })
            .map(|ct| (http::header::CONTENT_TYPE, ct))
            .collect();
        Cow::Owned(headers)
    }
}
