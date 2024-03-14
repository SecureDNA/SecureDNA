// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tools for implementing [`web_sys`] clients (WIP)

use http::HeaderValue;
use web_sys::Headers;

use crate::stream::{MessageError, DEFAULT_CONTENT_TYPE_STR};

/// Checks that the given header map has the expected content-type
///
/// If no `Content-Type` is provided, a default of `application/octet-stream` is assumed, per
/// [RFC 9110 section 8.3](https://httpwg.org/specs/rfc9110.html#rfc.section.8.3).
///
/// Currently returns an error if any `Content-Type` header is wrong. This needs to
/// be fixed to have proper HTTP semantics (case insensitivity, etc).
pub fn check_content_type(headers: &Headers, expected: &'static str) -> Result<(), MessageError> {
    // Not wrapping stream::check_content_type because I'm not sure what to do
    // if the String isn't a valid HeaderValue.
    let content_type = headers.get("Content-Type").ok().flatten();
    let content_type = content_type.unwrap_or_else(|| DEFAULT_CONTENT_TYPE_STR.to_owned());
    if content_type != expected {
        return Err(MessageError::WrongContentType {
            actual: content_type
                .try_into()
                .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
            expected: HeaderValue::from_static(expected),
        });
    }
    Ok(())
}

// TODO: add_ristrettos and from_response once it looks like we'll need those
