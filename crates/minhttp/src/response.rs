// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Response-related helpers

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::Response;
pub use hyper::StatusCode;
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HeaderValue, LOCATION};

/// Type-erased HTTP response
pub type GenericResponse = Response<BoxBody<Bytes, anyhow::Error>>;

/// Return an empty GenericResponse.
///
/// Because this is expected to be used with CORS preflight requests, it returns a 200 response
/// instead of 204 for compatibility with Firefox.
pub fn empty() -> GenericResponse {
    let body = Empty::new().map_err(anyhow::Error::from).boxed();
    Response::new(body)
}

/// Return a [`GenericResponse`] with known content.
pub fn full(
    status: StatusCode,
    content_type: &'static str,
    content: impl ToString,
) -> GenericResponse {
    let body = content.to_string().map_err(anyhow::Error::from).boxed();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(body)
        .unwrap()
}

/// Return a plain text response with known content.
pub fn text(status: StatusCode, content: impl ToString) -> GenericResponse {
    let content_type = "text/plain; charset=utf-8";
    full(status, content_type, content)
}

/// Return a JSON response with known content.
pub fn json(status: StatusCode, content: impl ToString) -> GenericResponse {
    let content_type = "application/json";
    full(status, content_type, content)
}

/// Return a plain text "404 not found" response with appropriate status code
pub fn not_found() -> GenericResponse {
    text(StatusCode::NOT_FOUND, "404 not found")
}

/// Return a redirect response
///
/// This returns an empty response with the given `status` code and
/// with the `Location` header set to `url`.
pub fn redirect<U>(status: StatusCode, url: U) -> GenericResponse
where
    HeaderValue: TryFrom<U, Error: Into<hyper::http::Error>>,
{
    Response::builder()
        .status(status)
        .header(LOCATION, url)
        .body(Empty::new().map_err(anyhow::Error::from).boxed())
        .unwrap()
}

/// Return a "303 See Other" response to the given `url`.
pub fn see_other<U>(url: U) -> GenericResponse
where
    HeaderValue: TryFrom<U, Error: Into<hyper::http::Error>>,
{
    redirect(StatusCode::SEE_OTHER, url)
}

/// Return a "307 Temporary Redirect" response to the given `url`.
pub fn temporary_redirect<U>(url: U) -> GenericResponse
where
    HeaderValue: TryFrom<U, Error: Into<hyper::http::Error>>,
{
    redirect(StatusCode::TEMPORARY_REDIRECT, url)
}

/// Return a "308 Permanent Redirect" response to the given `url`.
pub fn permanent_redirect<U>(url: U) -> GenericResponse
where
    HeaderValue: TryFrom<U, Error: Into<hyper::http::Error>>,
{
    redirect(StatusCode::PERMANENT_REDIRECT, url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_body(response: GenericResponse) -> Vec<u8> {
        let body = response.into_body().collect();
        futures::executor::block_on(body)
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn sanity_check_full_response() {
        let response = full(
            StatusCode::CREATED,
            "foo/bar",
            format_args!("double = {}, square = {}", 123 + 123, 123 * 123),
        );
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers().get(CONTENT_TYPE).unwrap(), "foo/bar");
        assert_eq!(to_body(response), b"double = 246, square = 15129");
    }

    #[test]
    fn sanity_check_text_response() {
        let name = "full_name";
        let value = "Bob Loblaw";
        let response = text(
            StatusCode::NOT_IMPLEMENTED,
            format_args!("{name} = {value:?}"),
        );
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(to_body(response), b"full_name = \"Bob Loblaw\"");
    }

    #[test]
    fn sanity_check_json_response() {
        let name = "primes";
        let value = [2, 3, 5, 7, 11, 13, 17];
        let response = json(
            StatusCode::NOT_IMPLEMENTED,
            format_args!("{{\"{name}\": {value:?}}}"),
        );
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(to_body(response), b"{\"primes\": [2, 3, 5, 7, 11, 13, 17]}");
    }
}
