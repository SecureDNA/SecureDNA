// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tools for implementing [`hyper`] servers

use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use futures::{Stream, TryStream, TryStreamExt};
use http::header::{HeaderValue, CONTENT_TYPE};
use http_body_util::StreamBody;
use hyper::body::{Body, Frame};
use hyper::{Request, Response};
use pin_project::pin_project;

pub use crate::stream::{
    check_content_length, HasShortErrorMsg, MessageError, RistrettoError, StreamableRistretto,
    HASH_SIZE,
};
use crate::stream::{check_content_type, decode, encode, ConversionError};
use crate::HasContentType;

/// Convert a [`Request`] into a fallible stream of `R`
///
/// Note that this checks that `Content-Type` matches
/// [`R::CONTENT_TYPE`](HasContentType::CONTENT_TYPE), but does not check the `Content-Length`;
/// see [`check_content_length`] for that.
pub fn from_request<B, R>(
    request: Request<B>,
) -> Result<impl Stream<Item = Result<R, RistrettoError<B::Error, ConversionError<R>>>>, MessageError>
where
    B: Body + Send + Sync,
    B::Error: Send + Sync,
    R: StreamableRistretto + Send + Sync,
{
    check_content_type(request.headers(), R::CONTENT_TYPE)?;
    Ok(decode(BodyStream(request.into_body())))
}

#[pin_project]
pub struct BodyStream<B>(#[pin] pub B);

impl<B> Stream for BodyStream<B>
where
    B: Body,
{
    type Item = Result<B::Data, B::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            return Poll::Ready(match ready!(this.0.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    Some(Ok(data))
                }
                Some(Err(err)) => Some(Err(err)),
                None => None,
            });
        }
    }
}

/// Produce a [`Response`] from a fallible stream of ristrettos
///
/// This is the same as [`to_response_with_buffer_size`] with a default `buffer_size` of 256KB.
pub fn to_response<S>(ristrettos: S) -> Response<impl Body<Data = Bytes, Error = S::Error>>
where
    S: TryStream + Send + Sync,
    S::Ok: StreamableRistretto,
    S::Error: HasShortErrorMsg + Send + Sync,
{
    let buffer_size = 256 * 1024;
    to_response_with_buffer_size(ristrettos, buffer_size)
}

/// Produce a [`Response`] from a fallible stream of ristrettos
///
/// This will appropriately set the `Content-Type`, and the body will buffer up
/// about `buffer_size` worth of data before producing a frame.
///
/// If `ristrettos` produces an error, it will be embedded in an invalid ristretto
/// that's included in the body. After said invalid ristretto is returned, an
/// error will be produced by the body.
pub fn to_response_with_buffer_size<S>(
    ristrettos: S,
    buffer_size: usize,
) -> Response<impl Body<Data = Bytes, Error = S::Error>>
where
    S: TryStream + Send + Sync,
    S::Ok: StreamableRistretto,
    S::Error: HasShortErrorMsg + Send + Sync,
{
    let body = StreamBody::new(encode(ristrettos, buffer_size).map_ok(Frame::data));
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(S::Ok::CONTENT_TYPE));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;

    use futures::{executor::block_on, StreamExt};
    use futures::{executor::block_on_stream as stream_to_iter, stream::iter as iter_to_stream};
    use http_body_util::BodyExt;
    use hyper::Request;

    use crate::stream::ShortErrorMsg;
    use crate::HasContentType;

    #[derive(Debug, PartialEq)]
    struct IdentityHash([u8; HASH_SIZE]);

    impl HasContentType for IdentityHash {
        const CONTENT_TYPE: &'static str = "application/x-identity-hash";
    }

    impl StreamableRistretto for IdentityHash {
        type Array = [u8; HASH_SIZE];

        type ConversionError = <[u8; HASH_SIZE] as TryInto<Self>>::Error;

        fn fit_error(error: &ShortErrorMsg) -> Self::Array {
            let mut data = [255; HASH_SIZE];
            data[1..HASH_SIZE - 1].copy_from_slice(error);
            data
        }
    }

    impl From<[u8; HASH_SIZE]> for IdentityHash {
        fn from(bytes: [u8; HASH_SIZE]) -> Self {
            Self(bytes)
        }
    }

    impl From<IdentityHash> for [u8; HASH_SIZE] {
        fn from(hash: IdentityHash) -> Self {
            hash.0
        }
    }

    #[test]
    fn smoke_test_from_request() {
        let body = http_body_util::Full::new(
            b"\0The contents of the first hash\0\
              \0The contents of a second hash.\0\
              \0interrupted data"
                .as_slice(),
        );
        let request = Request::post("/")
            .header("Content-Type", "application/x-identity-hash")
            .body(body)
            .unwrap();
        let ristrettos = from_request(request).unwrap().boxed();

        type RistrettoErr = RistrettoError<Infallible, Infallible>;

        let actual: Vec<Result<IdentityHash, RistrettoErr>> = stream_to_iter(ristrettos).collect();
        let expected = vec![
            Ok(IdentityHash(*b"\0The contents of the first hash\0")),
            Ok(IdentityHash(*b"\0The contents of a second hash.\0")),
            Err(RistrettoError::Incomplete {
                data: Bytes::from_static(b"\0interrupted data"),
            }),
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn from_request_checks_content_type() {
        let body = http_body_util::Full::new(b"".as_slice());
        let request = Request::post("/")
            .header("Content-Type", "application/x-wrong-type")
            .body(body)
            .unwrap();
        let Err(err) = from_request::<_, IdentityHash>(request) else {
            panic!("from_request() failed to catch incorrect content-type");
        };
        assert_eq!(
            err,
            MessageError::WrongContentType {
                actual: HeaderValue::from_static("application/x-wrong-type"),
                expected: HeaderValue::from_static("application/x-identity-hash"),
            }
        );
    }

    #[test]
    fn smoke_test_to_response() {
        let ristrettos: [Result<_, Infallible>; 2] = [
            Ok(IdentityHash(*b"\0The contents of the first hash\0")),
            Ok(IdentityHash(*b"\0The contents of a second hash.\0")),
        ];
        let stream = iter_to_stream(ristrettos);
        let response = to_response(stream);

        let content_types: Vec<_> = response.headers().get_all(CONTENT_TYPE).iter().collect();
        let expected_content_types = vec![HeaderValue::from_static("application/x-identity-hash")];
        assert_eq!(content_types, expected_content_types);

        let body = block_on(response.into_body().collect()).unwrap().to_bytes();
        let expected_body = Bytes::from_static(
            b"\0The contents of the first hash\0\
              \0The contents of a second hash.\0",
        );
        assert_eq!(body, expected_body);
    }
}
