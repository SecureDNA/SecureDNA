// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Response-related helpers

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, LOCATION};
use hyper::Response;
pub use hyper::StatusCode;

/// Holds a [`GenericResponse`], possibly wrapped in an [`ErrResponse`].
///
/// See [`ErrResponse`] for example use.
pub type ResponseResult = Result<GenericResponse, ErrResponse>;

/// Type-erased HTTP response
pub type GenericResponse = Response<BoxBody<Bytes, anyhow::Error>>;

/// Wrapper to easily convert displayable errors into [`GenericResponse`]s.
///
/// Errors are stringified via [`ToString::to_string`] then returned as a plain text
/// [`GenericResponse`] with a 400 status code.
///
/// See also [`ResponseResult`].
///
/// # Examples
///
/// ```
/// use hyper::{Request, Response, StatusCode};
/// use hyper::header::{HeaderValue, CONTENT_TYPE};
///
/// use minhttp::response::{self, text, ErrResponse, GenericResponse, ResponseResult};
///
/// fn repond<B>(request: Request<B>) -> GenericResponse {
///     match foo_handler(request) {
///         Ok(r) => r,
///         Err(ErrResponse(r)) => {
///             log_failure();
///             r
///         }
///     }
/// }
///
/// fn log_failure() {
///     unimplemented!()
/// }
///
/// fn foo_handler<B>(request: Request<B>) -> ResponseResult {
///     let content_type = request.headers().get(CONTENT_TYPE)
///         .ok_or(ErrResponse(text(StatusCode::BAD_REQUEST, "Oh no!")))?;
///     check_content_type(content_type)
///         .map_err(|e| ErrResponse(text(StatusCode::BAD_REQUEST, e)))?;
///
///     Ok(response::text(StatusCode::OK, "Woot!"))
/// }
///
/// struct ContentTypeError;
///
/// impl std::fmt::Display for ContentTypeError {
///     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
///         write!(f, "Wrong content type!")
///     }
/// }
///
/// fn check_content_type(content_type: &HeaderValue) -> Result<(), ContentTypeError> {
///     unimplemented!()
/// }
/// ```
pub struct ErrResponse(pub GenericResponse);

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

/// Return a "303 See Other" response with a Location header.
pub fn see_other<V>(url: V) -> GenericResponse
where
    hyper::header::HeaderValue: TryFrom<V>,
    <hyper::header::HeaderValue as TryFrom<V>>::Error: Into<hyper::http::Error>,
{
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(LOCATION, url)
        .body(Empty::new().map_err(anyhow::Error::from).boxed())
        .unwrap()
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

    #[test]
    fn sanity_check_err_response() {
        fn inner() -> ResponseResult {
            Err(ErrResponse(text(StatusCode::BAD_REQUEST, "oh no!")))?;
            todo!();
        }
        let ErrResponse(response) = inner().unwrap_err();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(to_body(response), b"oh no!");
    }
}
