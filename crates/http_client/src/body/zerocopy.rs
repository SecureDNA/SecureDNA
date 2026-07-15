// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers for streaming [`zerocopy`]-compatible types.
//!
//! See [`Streamed`] for an example.

use std::convert::Infallible;
use std::io::Cursor;
use std::marker::PhantomData;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures::{Stream, TryStream, TryStreamExt};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue};
use http_body_util::BodyDataStream;
use hyper::body::{Body, Frame, SizeHint};
use zerocopy::error::AlignedTryCastError;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

use streamed_ristretto::HasContentType;
use streamed_ristretto::stream::{MessageError, check_content_length, check_content_type};
use streamed_ristretto::util::{Chunked, chunked};

use super::{TryFromBody, TryIntoBody};
use crate::service::util::BoxedError;

/// Allows sending chunked fallible streams as [`Body`]s.
///
/// Note that by default, the stream is expected to be over `Result<impl Deref<Target=[T]>, E>`
/// where `T` implements [`HasContentType`], [`IntoBytes`] and [`Immutable`]. This potentially
/// allows for efficient zero-copy handling of data, but can be inconvenient. If you instead
/// would rather work with a streams of `Result<T, E>`, you can use [`Streamed::from_flattened`]
/// and [`Streamed::to_flattened`]; see the examples below.
///
/// # Example
///
/// ```
/// use std::convert::Infallible;
///
/// use futures::TryStreamExt;
/// use http::{header::CONTENT_TYPE, Response};
/// use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
///
/// use streamed_ristretto::HasContentType;
///
/// use http_client::body::zerocopy::Streamed;
/// use http_client::service::util::ServiceFn;
/// use http_client::BaseApiClient;
///
/// #[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
/// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// #[repr(C)]
/// struct Element([u8; 8]);
///
/// impl HasContentType for Element {
///     const CONTENT_TYPE: &'static str = "application/x-element";
/// }
///
/// # futures::executor::block_on(async {
/// let echo_service = ServiceFn::http(|request| async {
///     let response = Response::builder()
///         .header(CONTENT_TYPE, "application/x-element")
///         .body(request.into_body())
///         .unwrap();
///     Ok::<_, Infallible>(response)
/// });
/// let api_client = BaseApiClient::from(echo_service);
///
/// // Flattened:
///
/// let elements = [
///     Element(*b"foobar 1"),
///     Element(*b"foobar 2"),
///     Element(*b"foobar 3"),
///     Element(*b"foobar 4"),
/// ];
/// let stream = futures::stream::iter(elements.map(Ok::<_, Infallible>));
///
/// let response: Streamed<_> = api_client
///     .post("/url", Streamed::from_flattened(stream))
///     .await
///     .unwrap();
///
/// let results: Vec<_> = response
///     .to_flattened::<Element>()
///     .try_collect()
///     .await
///     .unwrap();
/// assert_eq!(results, elements);
///
/// // Chunked:
///
/// let chunked_elements = [
///     vec![
///         Element(*b"foobar 1"),
///         Element(*b"foobar 2"),
///         Element(*b"foobar 3"),
///     ],
///     vec![Element(*b"foobar 4"), Element(*b"foobar 5")],
/// ];
/// let request_data = Streamed {
///     chunks: futures::stream::iter(chunked_elements.clone().map(Ok::<_, Infallible>)),
///     total_elements: Some(5),
/// };
/// let Streamed {
///     chunks,
///     total_elements,
/// } = api_client.post("/url", request_data).await.unwrap();
///
/// let results: Vec<Vec<Element>> = chunks
///     .map_ok(Vec::<Element>::from_iter)
///     .try_collect()
///     .await
///     .unwrap();
/// assert_eq!(total_elements, Some(5));
/// assert_eq!(results, chunked_elements);
/// # });
/// ```
#[derive(Clone)]
pub struct Streamed<C> {
    /// A fallible [`Stream`] of chunks.
    ///
    /// Each chunk should be a [`Deref<Target=[T]>`] where `T` implements [`HasContentType`],
    /// [`IntoBytes`] and [`Immutable`].
    pub chunks: C,
    /// The expected number of items if [`chunks`](Self::chunks) is flattened without errors.
    ///
    /// This influences [`Body::size_hint`]. Note that differs from [`Stream::size_hint`] in that
    /// the actual number of elements may be less (if an error occurs midway through the [`Stream`]
    /// or more (if an error occurs after all elements have been sent).
    pub total_elements: Option<u64>,
}

impl<C> std::fmt::Debug for Streamed<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Streamed")
            .field("chunks", &..)
            .field("total_elements", &self.total_elements)
            .finish()
    }
}

/**************************************************
 * Types/impls related to flattening/unflattening *
 **************************************************/

impl<S> Streamed<Unflattened<S>> {
    /// Construct [`Streamed`] from an unchunked fallible [`Stream`].
    ///
    /// The passed [`Stream`] should yield [`Result`]s of individual elements, not chunks.
    ///
    /// This cannot safely infer the number of elements from the stream's
    /// [`size_hint`](Stream::size_hint), because some elements may be errors.
    pub fn from_flattened(stream: S) -> Self
    where
        S: TryStream,
    {
        Self {
            chunks: Unflattened(stream),
            total_elements: None,
        }
    }
}

/// Converts a fallible stream of elements into a fallible stream of single-element chunks.
///
/// This is just a concrete type for `stream.map_ok(AsSliceAdapter)`.
#[pin_project::pin_project]
pub struct Unflattened<S>(#[pin] S);

impl<S: TryStream> Stream for Unflattened<S> {
    type Item = Result<AsSliceAdapter<S::Ok>, S::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.project().0.try_poll_next(cx).map_ok(AsSliceAdapter)
    }
}

/// Adapt `T` to impl `Deref<Target=[T]>`
pub struct AsSliceAdapter<T>(T);

impl<T> Deref for AsSliceAdapter<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        std::slice::from_ref(&self.0)
    }
}

impl<S> Streamed<S> {
    /// Consume [`Streamed`] to produce a flattened [`Stream`].
    ///
    /// The resulting [`Stream`] does not have a specific [`size_hint`](Stream::size_hint)
    /// because the [`Body`] it's derived from may error out at any time, perhaps even after
    /// all data has been sent.
    pub fn to_flattened<T>(self) -> impl Stream<Item = Result<T, <S as TryStream>::Error>>
    where
        S: TryStream<Ok = StreamChunk<T>>,
        T: TryFromBytes + KnownLayout + Immutable + Unaligned,
    {
        self.chunks
            .map_ok(|chunk| futures::stream::iter(chunk.map(Ok)))
            .try_flatten()
    }
}

/*************************************************************
 * Types/impls related to conversions from streams to bodies *
 *************************************************************/

impl<T, S> TryIntoBody for Streamed<S>
where
    S: TryStream,
    S::Ok: Deref<Target = [T]>,
    T: HasContentType,
    StreamBody<S>: Body,
{
    const FORMAT_NAME: &'static str = T::CONTENT_TYPE; // Good enough for now.

    type Body = StreamBody<S>;
    type Error = Infallible;

    fn try_into_body(self, headers: &mut HeaderMap) -> Result<Self::Body, Self::Error> {
        let element_size: u64 = size_of::<T>().try_into().unwrap();
        let content_length = self
            .total_elements
            .and_then(|elements| elements.checked_mul(element_size));
        if let Some(content_length) = content_length {
            headers
                .entry(CONTENT_LENGTH)
                .or_insert(HeaderValue::from(content_length));
        }
        headers
            .entry(CONTENT_TYPE)
            .or_insert(HeaderValue::from_static(T::CONTENT_TYPE));
        Ok(StreamBody {
            stream: self.chunks,
            size: content_length,
        })
    }
}

/// Adaptor from a [`Stream`] to a [`Body`].
#[derive(Clone, Debug)]
#[pin_project::pin_project]
pub struct StreamBody<S> {
    #[pin]
    stream: S,
    size: Option<u64>,
}

impl<S> Body for StreamBody<S>
where
    S: TryStream,
    BodyChunk<S::Ok>: Buf,
{
    type Data = BodyChunk<S::Ok>;
    type Error = S::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        this.stream.try_poll_next(cx).map_ok(|chunk| {
            let buf = Cursor::new(AsRefAdapter(chunk));
            if let Some(size) = this.size {
                *size = buf
                    .remaining()
                    .try_into()
                    .ok()
                    .and_then(|len| size.checked_sub(len))
                    .expect("StreamBody larger than initial size");
            }
            Frame::data(buf)
        })
    }

    fn size_hint(&self) -> SizeHint {
        self.size.map(SizeHint::with_exact).unwrap_or_default()
    }
}

/// Chunk of a [`StreamBody`].
///
/// Implements [`Buf`] when `T: Deref<Target: IntoBytes + Immutable>`.
pub type BodyChunk<T> = Cursor<AsRefAdapter<T>>;

/// Adaptor delegating [`AsRef<[u8]>`] to [`IntoBytes`].
#[derive(Debug, PartialEq, Eq)]
pub struct AsRefAdapter<T>(T);

impl<T: Deref<Target: IntoBytes + Immutable>> AsRef<[u8]> for AsRefAdapter<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/*************************************************************
 * Types/impls related to conversions from bodies to streams *
 *************************************************************/

impl<T, B> TryFromBody<B> for Streamed<BodyStream<T, B>>
where
    T: HasContentType,
    B: Body + Send + 'static,
{
    const FORMAT_NAME: &'static str = T::CONTENT_TYPE; // Good enough for now.

    type Error = MessageError;

    async fn try_from_body(body: B, headers: &HeaderMap) -> Result<Self, Self::Error> {
        check_content_type(headers, T::CONTENT_TYPE)?;
        // We don't want a missing content length to be an error (so this is compatible with
        // arbitrary streams); the client can check `total_elements` if they want an exact length.
        let total_elements = match body.size_hint().exact() {
            None => None,
            content_len => Some(check_content_length(content_len, size_of::<T>())?),
        };
        Ok(Self {
            chunks: BodyStream {
                element_type: PhantomData,
                inner: chunked(BodyDataStream::new(body), size_of::<T>()),
            },
            total_elements,
        })
    }
}

/// Converts a [`Body`] to a [`Stream`]
#[pin_project::pin_project]
pub struct BodyStream<T, B: Body> {
    element_type: PhantomData<fn() -> T>,
    #[pin]
    inner: Chunked<BodyDataStream<B>>,
}

impl<T: TryFromBytes + KnownLayout + Immutable + Unaligned, B: Body> Stream for BodyStream<T, B> {
    type Item = Result<StreamChunk<T>, StreamedError<T, B::Error>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.project()
            .inner
            .try_poll_next(cx)
            .map_err(StreamedError::Stream)
            .map(|next| next.map(|element| element.and_then(StreamChunk::new)))
    }
}

/// An individual chunk of a [`BodyStream`] that implements `Deref<Target=[T]>`.
#[derive(Debug)]
pub struct StreamChunk<T> {
    element_type: PhantomData<fn() -> T>,
    bytes: Bytes,
}

impl<T: TryFromBytes + KnownLayout + Immutable + Unaligned> StreamChunk<T> {
    fn new<E>(mut buf: impl Buf) -> Result<Self, StreamedError<T, E>> {
        let chunk = StreamChunk {
            element_type: PhantomData,
            bytes: buf.copy_to_bytes(buf.remaining()),
        };

        // Check that our Deref impl ought to succeed
        let _: &[T] = TryFromBytes::try_ref_from_bytes(&chunk.bytes).map_err(|err| {
            let err = err.map_src(|_src| chunk.bytes.clone()).into();
            StreamedError::Cast(err)
        })?;

        Ok(chunk)
    }
}

impl<T> Clone for StreamChunk<T> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            element_type: PhantomData,
        }
    }
}

impl<T> Default for StreamChunk<T> {
    fn default() -> Self {
        Self {
            bytes: Bytes::default(),
            element_type: PhantomData,
        }
    }
}

impl<T: TryFromBytes + KnownLayout + Immutable + Unaligned> Deref for StreamChunk<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        // I suppose this could fail if the TryFromBytes impl isn't reproducible...
        // It's a shame this is checked twice. (the first time was in `StreamChunk::new`)
        // Oh well, hopefully it shouldn't be that expensive, and maybe the compiler can
        // eliminate the second checks?
        TryFromBytes::try_ref_from_bytes(&self.bytes)
            .expect("try_ref_from_bytes failed despite previously succeeding")
    }
}

impl<T: TryFromBytes + KnownLayout + Immutable + Unaligned> Iterator for StreamChunk<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        // (see comment above in Deref about this check happening twice)
        let buffer = self.bytes.split_to(size_of::<T>());
        let item = TryFromBytes::try_read_from_bytes(&buffer)
            .expect("try_read_from_bytes failed despite previously succeeding");
        Some(item)
    }
}

/// Error happening mid-stream while parsing an incoming body.
#[derive(Debug)]
pub enum StreamedError<T: TryFromBytes, E> {
    Stream(E),
    Cast(AlignedTryCastError<Bytes, [T]>),
}

impl<T, E> From<StreamedError<T, E>> for BoxedError
where
    T: TryFromBytes + KnownLayout + Immutable + Unaligned + 'static,
    E: Into<BoxedError>,
{
    fn from(err: StreamedError<T, E>) -> BoxedError {
        // Not sure if unwrapping the different cases is the right thing to do or not...
        match err {
            StreamedError::Stream(err) => err.into(),
            StreamedError::Cast(err) => err.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::StreamExt;
    use http::{HeaderMap, HeaderValue};
    use http_body_util::BodyExt;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

    #[derive(
        Copy, Clone, Debug, PartialEq, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    )]
    #[repr(C)]
    struct Element([u8; 8]);

    impl HasContentType for Element {
        const CONTENT_TYPE: &'static str = "application/x-element";
    }

    fn content_type_headers() -> HeaderMap {
        let content_type = HeaderValue::from_static(Element::CONTENT_TYPE);
        HeaderMap::from_iter([(CONTENT_TYPE, content_type)])
    }

    #[tokio::test]
    async fn smoke_test_chunked_stream_to_body() {
        let chunks = [
            vec![
                Element(*b"foobar 1"),
                Element(*b"foobar 2"),
                Element(*b"foobar 3"),
            ],
            vec![Element(*b"foobar 4"), Element(*b"foobar 5")],
        ]
        .map(Ok::<_, Infallible>);

        let mut headers = HeaderMap::new();
        let request_data = Streamed {
            chunks: futures::stream::iter(chunks.clone()),
            total_elements: Some(5),
        };
        let body = request_data.try_into_body(&mut headers).unwrap();

        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/x-element");
        assert_eq!(body.size_hint().exact(), Some(5 * 8));
        let data = body.collect().await.unwrap().to_bytes();
        assert_eq!(&*data, b"foobar 1foobar 2foobar 3foobar 4foobar 5");
    }

    #[tokio::test]
    async fn smoke_test_flattened_stream_to_body() {
        let chunks = [
            Element(*b"foobar 1"),
            Element(*b"foobar 2"),
            Element(*b"foobar 3"),
            Element(*b"foobar 4"),
            Element(*b"foobar 5"),
        ]
        .map(Ok::<_, Infallible>);

        let mut headers = HeaderMap::new();
        let request_data = Streamed::from_flattened(futures::stream::iter(chunks));
        let body = request_data.try_into_body(&mut headers).unwrap();

        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/x-element");
        assert_eq!(body.size_hint().exact(), None);
        let data = body.collect().await.unwrap().to_bytes();
        assert_eq!(&*data, b"foobar 1foobar 2foobar 3foobar 4foobar 5");
    }

    #[tokio::test]
    async fn smoke_test_body_to_chunked_stream() {
        let body = "foobar 1foobar 2foobar 3".to_owned();
        let Streamed {
            mut chunks,
            total_elements,
        } = Streamed::try_from_body(body, &content_type_headers())
            .await
            .unwrap();

        assert_eq!(total_elements, Some(3));

        // Ugh... trying to flatten fallible streams with combinators is worse.
        let mut elements = Vec::<Element>::new();
        while let Some(chunk) = chunks.next().await {
            elements.extend_from_slice(&chunk.unwrap());
        }

        let expected_elements = [
            Element(*b"foobar 1"),
            Element(*b"foobar 2"),
            Element(*b"foobar 3"),
        ];
        assert_eq!(elements, expected_elements);
    }

    #[tokio::test]
    async fn smoke_test_body_to_flattened_stream() {
        let body = "foobar 1foobar 2foobar 3".to_owned();
        let streamed = Streamed::try_from_body(body, &content_type_headers())
            .await
            .unwrap()
            .to_flattened::<Element>();

        let elements: Vec<_> = streamed.try_collect().await.unwrap();

        let expected_elements = [
            Element(*b"foobar 1"),
            Element(*b"foobar 2"),
            Element(*b"foobar 3"),
        ];
        assert_eq!(elements, expected_elements);
    }

    #[tokio::test]
    async fn frames_do_not_need_to_be_aligned_to_elements() {
        let body_chunks = ["foo", "bar 1f", "oobar 2"]
            .map(|s| Bytes::from_static(s.as_bytes()))
            .map(Frame::data)
            .map(Ok::<_, Infallible>);
        let body = http_body_util::StreamBody::new(futures::stream::iter(body_chunks));
        let streamed = Streamed::try_from_body(body, &content_type_headers())
            .await
            .unwrap()
            .to_flattened::<Element>();

        let elements: Vec<_> = streamed.try_collect().await.unwrap();

        let expected_elements = [Element(*b"foobar 1"), Element(*b"foobar 2")];
        assert_eq!(elements, expected_elements);
    }

    #[tokio::test]
    async fn bad_content_types_are_rejected() {
        let body = "foobar 1".to_owned();
        let err = Streamed::<BodyStream<Element, _>>::try_from_body(body, &HeaderMap::new())
            .await
            .unwrap_err();
        assert!(matches!(err, MessageError::WrongContentType { .. }));

        let body = "foobar 1".to_owned();
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("wrong/type"));
        let err = Streamed::<BodyStream<Element, _>>::try_from_body(body, &headers)
            .await
            .unwrap_err();
        assert!(matches!(err, MessageError::WrongContentType { .. }));
    }

    #[tokio::test]
    async fn size_hint_for_partial_element_fails_early() {
        let body = "foobar 1foo".to_owned();
        let err = Streamed::<BodyStream<Element, _>>::try_from_body(body, &content_type_headers())
            .await
            .unwrap_err();
        assert!(matches!(err, MessageError::InvalidContentLength(Some(11))));
    }

    #[tokio::test]
    async fn partial_elements_result_in_errors() {
        // Doing the body in this roundabout way prevents size hints.
        let frames = [Ok::<_, Infallible>(Frame::data(b"foobar 1foo".as_slice()))];
        let body = http_body_util::StreamBody::new(futures::stream::iter(frames));

        // Note that the initial call doesn't fail...
        let mut elements = Streamed::try_from_body(body, &content_type_headers())
            .await
            .unwrap()
            .to_flattened::<Element>();
        // The first element is complete, so it's extracted just fine...
        let _ = elements.next().await.unwrap();
        // ...but the body stops in the middle of the second element, resulting in an error
        let err = elements.next().await.unwrap().unwrap_err();
        assert!(matches!(err, StreamedError::Cast(_)));
    }

    #[tokio::test]
    async fn errors_are_propagated_from_streams_to_bodies() {
        let chunks = futures::stream::iter([
            Ok(vec![Element(*b"foobar 1"), Element(*b"foobar 2")]),
            Err("oh no!"),
        ]);
        let request_data = Streamed {
            chunks,
            total_elements: None,
        };
        let mut body = request_data.try_into_body(&mut HeaderMap::new()).unwrap();
        // The first attempt to read the body returns the first frame...
        body.frame().await.unwrap().unwrap();
        // ...but the second hits an error
        let err = body.frame().await.unwrap().unwrap_err();
        assert_eq!(err, "oh no!");
    }

    #[tokio::test]
    async fn errors_are_propagated_from_bodies_to_streams() {
        // Doing the body in this roundabout way prevents size hints.
        let frames = [
            Ok(Frame::data(b"foobar 1foobar 2".as_slice())),
            Err("oh no!"),
        ];
        let body = http_body_util::StreamBody::new(futures::stream::iter(frames));

        let mut elements = Streamed::try_from_body(body, &content_type_headers())
            .await
            .unwrap()
            .to_flattened::<Element>();
        // The first two elements are complete, so they're extracted just fine...
        let _ = elements.next().await.unwrap();
        let _ = elements.next().await.unwrap();
        // ...but the body stops in the middle of the second element, resulting in an error
        let err = elements.next().await.unwrap().unwrap_err();
        assert!(matches!(err, StreamedError::Stream("oh no!")));
    }
}
