// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lowish-level semi-framework-agnostic tools for working with streamed ristrettos

use std::fmt::Debug;
use std::io::Cursor;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use doprf::tagged::TaggedHash;
use futures::{Stream, TryStream};
use http::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use pin_project::pin_project;
use thiserror::Error;

use doprf::prf::{CompletedHashValue, Query};

use crate::util;
use crate::HasContentType;

/// Size of compressed ristrettos in bytes
pub const HASH_SIZE: usize = 32;

/// An ASCII-encoded error message that can be squeezed between two 0xFF bytes
/// of an invalid Ristretto hash.
pub type ShortErrorMsg = [u8; HASH_SIZE - 2];

// See RFC 9110, section 8.3
pub(crate) const DEFAULT_CONTENT_TYPE_STR: &str = "application/octet-stream";
pub(crate) static DEFAULT_CONTENT_TYPE: HeaderValue =
    HeaderValue::from_static(DEFAULT_CONTENT_TYPE_STR);

/// Common requirements for a type to be transfered via streaming ristretto format
pub trait StreamableRistretto:
    HasContentType
    + TryFrom<Self::Array, Error = Self::ConversionError>
    + Into<Self::Array>
    + Send
    + Sync
    + 'static
{
    /// The array type holding one encoded Ristretto, e.g. [u8; 32] (pure
    /// Ristrettos) or [u8; 36] (Ristrettos with headers).
    type Array: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    const SIZE: usize = std::mem::size_of::<Self::Array>();

    // Workaround for lack of associated type bounds
    type ConversionError: std::fmt::Debug + Send + Sync;

    /// Fit a Ristretto-sized error message in a unit of the stream. This should
    /// place the 30-byte error message in the middle of the 32-byte location
    /// where the encoded Ristretto hash would go, surrounded by 0xFF bytes.
    fn fit_error(error: &ShortErrorMsg) -> Self::Array;
}

impl StreamableRistretto for Query {
    type Array = [u8; HASH_SIZE];
    type ConversionError = <Self::Array as TryInto<Self>>::Error;

    fn fit_error(error: &ShortErrorMsg) -> Self::Array {
        let mut data = [255; HASH_SIZE];
        data[1..HASH_SIZE - 1].copy_from_slice(error);
        data
    }
}

impl StreamableRistretto for CompletedHashValue {
    type Array = [u8; HASH_SIZE];
    type ConversionError = <Self::Array as TryInto<Self>>::Error;

    fn fit_error(error: &ShortErrorMsg) -> Self::Array {
        Query::fit_error(error)
    }
}

impl StreamableRistretto for TaggedHash {
    type Array = [u8; TaggedHash::SIZE];
    type ConversionError = <Self::Array as TryInto<Self>>::Error;

    fn fit_error(error: &ShortErrorMsg) -> Self::Array {
        let mut data = [255; TaggedHash::SIZE];
        data[4 + 1..TaggedHash::SIZE - 1].copy_from_slice(error);
        data
    }
}

/// Allow embedding an error into an invalid packed ristretto
pub trait HasShortErrorMsg {
    fn short_err_msg(&self) -> ShortErrorMsg;
}

impl HasShortErrorMsg for std::convert::Infallible {
    fn short_err_msg(&self) -> ShortErrorMsg {
        unreachable!()
    }
}

/// Streamed ristretto parsing errors that are detectable upfront
#[derive(Debug, Error, PartialEq)]
pub enum MessageError {
    #[error("wrong Content-Type; got {actual:?}, expected {expected:?}")]
    WrongContentType {
        actual: HeaderValue,
        expected: HeaderValue,
    },
    #[error("invalid content length: {0:?}")]
    InvalidContentLength(Option<u64>),
}

/// Streamed ristretto errors occuring mid-stream
#[derive(Debug, Error, PartialEq)]
pub enum RistrettoError<SE = std::convert::Infallible, CE: Debug = std::convert::Infallible> {
    /// Stream errors, such as problems reading from a socket
    #[error("stream error")]
    Stream(SE),
    /// The stream ended (or encountered an error) partway through a ristretto
    #[error("incomplete data {data:?}")]
    Incomplete { data: Bytes },
    /// Unable to interpret a chunk of bytes as a ristretto
    #[error("data {data:?} cannot be converted to ristretto because {error:?}")]
    Conversion { data: Bytes, error: CE },
}

impl<SE, CE: Debug> HasShortErrorMsg for RistrettoError<SE, CE> {
    fn short_err_msg(&self) -> ShortErrorMsg {
        match self {
            Self::Stream(_) => *b"Error reading ristrettos.\0\0\0\0\0",
            Self::Incomplete { .. } => *b"Ristretto was incomplete.\0\0\0\0\0",
            Self::Conversion { .. } => *b"Ristretto was invalid.\0\0\0\0\0\0\0\0",
        }
    }
}

pub type ConversionError<R> = <<R as StreamableRistretto>::Array as TryInto<R>>::Error;

/// Checks that the given header map has the expected content-type
///
/// If no `Content-Type` is provided, a default of `application/octet-stream` is assumed, per
/// [RFC 9110 section 8.3](https://httpwg.org/specs/rfc9110.html#rfc.section.8.3).
///
/// Currently returns an error if any `Content-Type` header is wrong. This needs to
/// be fixed to have proper HTTP semantics (case insensitivity, treating multiple
/// headers as joined by commas, etc).
pub fn check_content_type(headers: &HeaderMap, expected: &'static str) -> Result<(), MessageError> {
    // Easier to check that all content types are expected than to bother with MessageError::DuplicateHeaders
    let fallback = (!headers.contains_key(CONTENT_TYPE)).then_some(&DEFAULT_CONTENT_TYPE);
    let mut content_types = headers.get_all(CONTENT_TYPE).iter().chain(fallback);
    if let Some(wrong_content_type) = content_types.find(|&ct| ct != expected) {
        return Err(MessageError::WrongContentType {
            actual: wrong_content_type.clone(),
            expected: HeaderValue::from_static(expected),
        });
    }
    Ok(())
}

/// Checks the message's content length and returns the corresponding number of ristrettos
///
/// `content_length` is intended to be obtained from an HTTP library's size hint (and is
/// therefore measured in bytes), NOT directly from the `Content-Length` header, in order
/// to ensure we're interpreting length consistently with the HTTP library.
///
/// Errors out if `content_length` is `None` or does not correspond with a whole number of hashes.
pub fn check_content_length(
    content_length: Option<u64>,
    hash_size: usize,
) -> Result<u64, MessageError> {
    match content_length {
        Some(content_length) if content_length % (hash_size as u64) == 0 => {
            Ok(content_length / (hash_size as u64))
        }
        _ => Err(MessageError::InvalidContentLength(content_length)),
    }
}

/// Adapt a fallible [`Buf`] stream into a fallible `R` stream.
///
/// The `stream` argument is expected to provide a series of [`Buf`]s that are joined together
/// and parsed into `R`s, which are yielded one at a time. The [`Buf`] boundaries may be
/// anywhere; they are not required to occur at multiples of [`HASH_SIZE`]. This attempts
/// to hold on to `stream`'s buffers for as short a time as possible to minimize memory
/// usage.
///
/// If an error occurs, the returned stream produces a [`RistrettoError`]. Currently,
/// an unaligned error (occurring in the middle of a partial `R`) may result in
/// [`RistrettoError::Incomplete`] being produced by the stream before the
/// [`RistrettoError::Stream`] that caused the error. After such an unaligned
/// error occurs, this stream adapter can no longer be relied on to produce valid
/// results.
pub fn decode<S, R>(stream: S) -> Decoder<S, R>
where
    S: TryStream,
    S::Ok: Buf,
    R: StreamableRistretto,
{
    Decoder {
        inner: util::chunked(stream, R::SIZE),
        chunk: Bytes::new(),
        ristretto_type: PhantomData,
    }
}

/// Adapts a fallible [`Buf`] stream into a fallible `R` stream.
///
/// Constructed with [`decode`]; see its docs.
#[pin_project]
pub struct Decoder<S, R>
where
    S: TryStream,
    S::Ok: Buf,
{
    #[pin]
    inner: util::Chunked<S>,
    chunk: Bytes,
    ristretto_type: PhantomData<R>,
}

impl<S, R> Stream for Decoder<S, R>
where
    S: TryStream,
    S::Ok: Buf,
    R: StreamableRistretto,
{
    type Item = Result<R, RistrettoError<S::Error, ConversionError<R>>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        while this.chunk.is_empty() {
            *this.chunk = match ready!(this.inner.as_mut().poll_next(cx)) {
                Some(Ok(chunk)) => chunk,
                Some(Err(err)) => return Poll::Ready(Some(Err(RistrettoError::Stream(err)))),
                None => return Poll::Ready(None),
            };
        }

        let next = this.chunk.split_to(this.chunk.len().min(R::SIZE)); // short if err occurs
        let ristretto = <R::Array>::try_from(&*next)
            .map_err(|_| RistrettoError::Incomplete { data: next.clone() })
            .and_then(|hash| {
                hash.try_into().map_err(|error| RistrettoError::Conversion {
                    data: next.clone(),
                    error,
                })
            });

        Poll::Ready(Some(ristretto))
    }
}

/// Adapts a fallible stream into a fallible [`Bytes`] stream.
///
/// The `stream` is expected to produce values that can be converted into [`HASH_SIZE`] bytes,
/// which will be buffered up into vaguely `buffer_size` chunks.
///
/// If `stream` produces an error, that error will be embedded into an invalid ristretto that
/// gets appended to the current buffer. The buffer is then returned, followed by the error
/// that caused the problem.
pub fn encode<S>(stream: S, buffer_size: usize) -> Encoder<S>
where
    S: TryStream,
    S::Ok: StreamableRistretto,
    S::Error: HasShortErrorMsg,
{
    let inlined = RistrettoEncoder {
        inner: stream,
        next_error: None,
    };
    let buffered = util::buffered(inlined, buffer_size);
    Encoder(buffered)
}

/// Adapts a fallible `R` stream into a fallible [`Bytes`] stream.
///
/// Constructed with [`encode`]; see its docs.
#[pin_project]
pub struct Encoder<S>(#[pin] util::Buffered<RistrettoEncoder<S>>)
where
    S: TryStream,
    S::Ok: StreamableRistretto,
    S::Error: HasShortErrorMsg;

impl<S> Stream for Encoder<S>
where
    S: TryStream,
    S::Ok: StreamableRistretto,
    S::Error: HasShortErrorMsg,
{
    type Item = Result<Bytes, S::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.project().0.poll_next(cx)
    }
}

// Converts valid ristrettos to HASH_SIZE byte chunks and passes them through.
// Errors are embedded in invalid ristrettos, which are returned ahead of the error.
#[pin_project]
struct RistrettoEncoder<S: TryStream> {
    #[pin]
    inner: S,
    next_error: Option<S::Error>,
}

impl<S> Stream for RistrettoEncoder<S>
where
    S: TryStream,
    S::Ok: StreamableRistretto,
    S::Error: HasShortErrorMsg,
{
    type Item = Result<Cursor<<S::Ok as StreamableRistretto>::Array>, S::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if let Some(err) = this.next_error.take() {
            return Poll::Ready(Some(Err(err)));
        }
        let hash_data = match ready!(this.inner.try_poll_next(cx)) {
            Some(Ok(ristretto)) => ristretto.into(),
            Some(Err(err)) => {
                let data = <S::Ok as StreamableRistretto>::fit_error(&err.short_err_msg());
                *this.next_error = Some(err);
                data
            }
            None => return Poll::Ready(None),
        };
        Poll::Ready(Some(Ok(Cursor::new(hash_data))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use futures::StreamExt;
    use futures::{executor::block_on_stream as stream_to_iter, stream::iter as iter_to_stream};
    use http::HeaderName;
    use quickcheck_macros::quickcheck;

    #[derive(Debug, PartialEq)]
    struct IdentityHash([u8; HASH_SIZE]);

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

    impl HasContentType for IdentityHash {
        const CONTENT_TYPE: &'static str = "application/x-identity-hash";
    }

    impl StreamableRistretto for IdentityHash {
        type Array = [u8; HASH_SIZE];

        type ConversionError = <[u8; HASH_SIZE] as TryInto<Self>>::Error;

        fn fit_error(error: &ShortErrorMsg) -> Self::Array {
            <Query as StreamableRistretto>::fit_error(error)
        }
    }

    #[derive(Debug, PartialEq)]
    struct FallibleHash([u8; HASH_SIZE]);

    impl TryFrom<[u8; HASH_SIZE]> for FallibleHash {
        type Error = SomeError;

        fn try_from(bytes: [u8; HASH_SIZE]) -> Result<Self, Self::Error> {
            let val = bytes.as_slice().get_i32_le();
            if val == 0 {
                Ok(Self(bytes))
            } else {
                Err(SomeError(val))
            }
        }
    }

    impl HasContentType for FallibleHash {
        const CONTENT_TYPE: &'static str = "application/x-fallible-hash";
    }

    impl From<FallibleHash> for [u8; HASH_SIZE] {
        fn from(hash: FallibleHash) -> Self {
            hash.0
        }
    }

    impl StreamableRistretto for FallibleHash {
        type Array = [u8; HASH_SIZE];

        type ConversionError = <[u8; HASH_SIZE] as TryInto<Self>>::Error;

        fn fit_error(error: &ShortErrorMsg) -> Self::Array {
            <Query as StreamableRistretto>::fit_error(error)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct SomeError(i32);

    fn to_headers(pairs: impl IntoIterator<Item = (&'static str, &'static str)>) -> HeaderMap {
        pairs
            .into_iter()
            .map(|(k, v)| (HeaderName::from_static(k), HeaderValue::from_static(v)))
            .collect()
    }

    #[derive(Debug, PartialEq)]
    struct ShortErr(ShortErrorMsg);

    impl HasShortErrorMsg for ShortErr {
        fn short_err_msg(&self) -> ShortErrorMsg {
            self.0
        }
    }

    #[test]
    fn check_content_type_accepts_matching_type() {
        assert_eq!(
            check_content_type(
                &to_headers([("content-type", "application/x-foo")]),
                "application/x-foo"
            ),
            Ok(())
        );
        assert_eq!(
            check_content_type(
                &to_headers([("content-type", "application/x-bar")]),
                "application/x-bar"
            ),
            Ok(())
        );
    }

    #[test]
    fn check_content_type_rejects_missing_header() {
        assert_eq!(
            check_content_type(&HeaderMap::new(), "application/x-foo"),
            Err(MessageError::WrongContentType {
                actual: HeaderValue::from_static("application/octet-stream"),
                expected: HeaderValue::from_static("application/x-foo")
            })
        );
    }

    #[test]
    fn check_content_type_rejects_any_wrong_content_type() {
        assert_eq!(
            check_content_type(
                &to_headers([("content-type", "application/x-bar")]),
                "application/x-foo"
            ),
            Err(MessageError::WrongContentType {
                actual: HeaderValue::from_static("application/x-bar"),
                expected: HeaderValue::from_static("application/x-foo")
            })
        );
        assert_eq!(
            check_content_type(
                &to_headers([
                    ("content-type", "application/x-foo"),
                    ("content-type", "application/x-bar")
                ]),
                "application/x-foo"
            ),
            Err(MessageError::WrongContentType {
                actual: HeaderValue::from_static("application/x-bar"),
                expected: HeaderValue::from_static("application/x-foo")
            })
        );
        assert_eq!(
            check_content_type(
                &to_headers([
                    ("content-type", "application/x-bar"),
                    ("content-type", "application/x-foo")
                ]),
                "application/x-foo"
            ),
            Err(MessageError::WrongContentType {
                actual: HeaderValue::from_static("application/x-bar"),
                expected: HeaderValue::from_static("application/x-foo")
            })
        );
    }

    // NOTE: We're not specifying how to behave if multiple correct content-types are supplied.

    #[test]
    fn smoke_test_check_content_length() {
        let hash_size = HASH_SIZE as u64;
        assert_eq!(check_content_length(Some(0), HASH_SIZE), Ok(0));
        assert_eq!(check_content_length(Some(hash_size), HASH_SIZE), Ok(1));
        assert_eq!(check_content_length(Some(2 * hash_size), HASH_SIZE), Ok(2));
        assert_eq!(check_content_length(Some(3 * hash_size), HASH_SIZE), Ok(3));
        assert_eq!(check_content_length(Some(4 * hash_size), HASH_SIZE), Ok(4));
        assert_eq!(
            check_content_length(None, HASH_SIZE),
            Err(MessageError::InvalidContentLength(None))
        );
        assert_eq!(
            check_content_length(Some(1), HASH_SIZE),
            Err(MessageError::InvalidContentLength(Some(1)))
        );
        assert_eq!(
            check_content_length(Some(hash_size - 1), HASH_SIZE),
            Err(MessageError::InvalidContentLength(Some(hash_size - 1)))
        );
        assert_eq!(
            check_content_length(Some(hash_size + 1), HASH_SIZE),
            Err(MessageError::InvalidContentLength(Some(hash_size + 1)))
        );
    }

    #[test]
    fn smoke_test_decode() {
        let data: [u8; 128] = std::array::from_fn(|i| i as _);
        let chunks = [&data[..8], &data[8..108], &data[108..]];
        let bufs = chunks.into_iter().map(|c| Ok(Cursor::new(c)));
        let stream = iter_to_stream(bufs);
        let decoded = decode(stream).boxed();

        let actual: Result<Vec<IdentityHash>, RistrettoError<()>> =
            stream_to_iter(decoded).collect();
        let expected: Vec<_> = data
            .chunks(32)
            .map(|c| IdentityHash(c.try_into().unwrap()))
            .collect();

        assert_eq!(actual.unwrap(), expected);
    }

    #[test]
    fn decode_handles_stream_errors() {
        let chunks = [
            Ok([0; 36].as_slice()),
            Err(SomeError(123)),
            Ok([0; 28].as_slice()),
        ];
        let bufs = chunks.into_iter().map(|result| result.map(Cursor::new));
        let stream = iter_to_stream(bufs);
        let decoded = decode(stream).boxed();

        let actual: Vec<Result<IdentityHash, RistrettoError<SomeError>>> =
            stream_to_iter(decoded).collect();
        let expected: Vec<Result<IdentityHash, RistrettoError<SomeError>>> = vec![
            Ok(IdentityHash([0; 32])),
            Err(RistrettoError::Incomplete {
                data: Bytes::from([0; 4].as_slice()),
            }),
            Err(RistrettoError::Stream(SomeError(123))),
            Err(RistrettoError::Incomplete {
                data: Bytes::from([0; 28].as_slice()),
            }),
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn decode_handles_conversion_errors() {
        let mut data = [0; 64];
        data[32] = 123;
        let chunk = Result::<_, ()>::Ok(Cursor::new(&data));
        let stream = iter_to_stream(std::iter::once(chunk));
        let decoded = decode(stream).boxed();

        let actual: Vec<Result<FallibleHash, _>> = stream_to_iter(decoded).collect();
        let expected: Vec<Result<_, RistrettoError<(), _>>> = vec![
            Ok(FallibleHash(data[..32].try_into().unwrap())),
            Err(RistrettoError::Conversion {
                data: Bytes::copy_from_slice(&data[32..]),
                error: SomeError(123),
            }),
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn decode_handles_partial_hash_errors() {
        let chunk = Result::<_, ()>::Ok(Cursor::new(&[0; 33]));
        let stream = iter_to_stream(std::iter::once(chunk));
        let decoded = decode(stream).boxed();

        let actual: Vec<Result<IdentityHash, _>> = stream_to_iter(decoded).collect();
        let expected = vec![
            Ok(IdentityHash([0; 32])),
            Err(RistrettoError::Incomplete {
                data: Bytes::copy_from_slice(&[0]),
            }),
        ];

        assert_eq!(actual, expected);
    }

    #[quickcheck]
    fn decode_properly_concats_and_converts_everything(mut chunks: Vec<Vec<u8>>) -> bool {
        let length: usize = chunks.iter().map(|c| c.len()).sum();
        // This is just testing the happy path, so pad things to prevent a partial hash.
        let remainder = vec![0; (HASH_SIZE - length % HASH_SIZE) % HASH_SIZE];
        chunks.push(remainder);

        let concatted: Vec<_> = chunks.iter().flatten().copied().collect();

        let bufs = chunks.into_iter().map(|chunk| Ok(Cursor::new(chunk)));
        let stream = iter_to_stream(bufs);
        let decoded = decode::<_, IdentityHash>(stream).boxed();

        let actual: Result<Vec<IdentityHash>, RistrettoError<()>> =
            stream_to_iter(decoded).collect();
        let expected: Vec<_> = concatted
            .chunks(HASH_SIZE)
            .map(|c| IdentityHash(c.try_into().unwrap()))
            .collect();

        actual.unwrap() == expected
    }

    #[test]
    fn smoke_test_encode() {
        let ristrettos = [
            Ok(IdentityHash(*b"\0The contents of the first hash\0")),
            Ok(IdentityHash(*b"\0The contents of a second hash.\0")),
            Err(ShortErr(*b"An unknown error has occurred.")),
        ];

        let stream = iter_to_stream(ristrettos);
        let buffer_size = 256;
        let encoded = encode(stream, buffer_size);

        let actual: Vec<Result<Bytes, ShortErr>> = stream_to_iter(encoded).collect();
        let expected = vec![
            Ok(Bytes::from_static(
                b"\0The contents of the first hash\0\
                                    \0The contents of a second hash.\0\
                                    \xFFAn unknown error has occurred.\xFF",
            )),
            Err(ShortErr(*b"An unknown error has occurred.")),
        ];

        assert_eq!(actual, expected);
    }

    #[derive(Debug, PartialEq)]
    struct LongHash([u8; 42]);

    impl From<[u8; 42]> for LongHash {
        fn from(bytes: [u8; 42]) -> Self {
            Self(bytes)
        }
    }

    impl From<LongHash> for [u8; 42] {
        fn from(hash: LongHash) -> Self {
            hash.0
        }
    }

    impl HasContentType for LongHash {
        const CONTENT_TYPE: &'static str = "application/x-long-hash";
    }

    impl StreamableRistretto for LongHash {
        type Array = [u8; 42];

        type ConversionError = <[u8; 42] as TryInto<Self>>::Error;

        fn fit_error(error: &ShortErrorMsg) -> Self::Array {
            let mut data = [255; 42];
            data[11..41].copy_from_slice(error);
            data
        }
    }

    #[test]
    fn smoke_test_long_decode() {
        let data: [u8; 4 * 42] = std::array::from_fn(|i| i as _);
        let chunks = [&data[..8], &data[8..108], &data[108..]];
        let bufs = chunks.into_iter().map(|c| Ok(Cursor::new(c)));
        let stream = iter_to_stream(bufs);
        let decoded = decode(stream).boxed();

        let actual: Result<Vec<LongHash>, RistrettoError<()>> = stream_to_iter(decoded).collect();
        let expected: Vec<_> = data
            .chunks(42)
            .map(|c| LongHash(c.try_into().unwrap()))
            .collect();

        assert_eq!(actual.unwrap(), expected);
    }

    #[test]
    fn smoke_test_long_encode() {
        let ristrettos = [
            Ok(LongHash(*b"\0The contents of the first loooooong hash\0")),
            Ok(LongHash(*b"\0The contents of a second loooooong hash.\0")),
            Err(ShortErr(*b"An unknown error has occurred.")),
        ];

        let stream = iter_to_stream(ristrettos);
        let buffer_size = 256;
        let encoded = encode(stream, buffer_size);

        let actual: Vec<Result<Bytes, ShortErr>> = stream_to_iter(encoded).collect();
        let expected = vec![
            Ok(Bytes::from_static(
                b"\0The contents of the first loooooong hash\0\
                \0The contents of a second loooooong hash.\0\
                \xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFFAn unknown error has occurred.\xFF",
            )),
            Err(ShortErr(*b"An unknown error has occurred.")),
        ];

        assert_eq!(actual, expected);
    }
}
