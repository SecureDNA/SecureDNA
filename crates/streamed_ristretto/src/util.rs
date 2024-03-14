// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt, TryStream};
use pin_project::pin_project;

pub fn chunked<S>(stream: S, element_size: usize) -> Chunked<S>
where
    S: TryStream,
    S::Ok: Buf,
{
    Chunked::with_element_size(element_size, stream)
}

#[pin_project]
pub struct Chunked<S>(#[pin] Buffered<futures::stream::Flatten<AlignedSplitStream<S>>>)
where
    S: TryStream,
    S::Ok: Buf;

impl<S> Chunked<S>
where
    S: TryStream,
    S::Ok: Buf,
{
    fn with_element_size(element_size: usize, stream: S) -> Self {
        let aligned = AlignedSplitStream::new(stream, element_size).flatten();
        let buffered = Buffered::with_chunk_size(element_size, aligned);
        Chunked(buffered)
    }
}

impl<S> Stream for Chunked<S>
where
    S: TryStream,
    S::Ok: Buf,
{
    type Item = Result<Bytes, S::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.project().0.poll_next(cx)
    }
}

#[pin_project]
struct AlignedSplitStream<S> {
    #[pin]
    inner: S,
    splitter: AlignedSplitter,
}

impl<S> AlignedSplitStream<S> {
    fn new(inner: S, element_size: usize) -> Self {
        Self {
            inner,
            splitter: AlignedSplitter::new(element_size),
        }
    }
}

impl<S> Stream for AlignedSplitStream<S>
where
    S: TryStream,
    S::Ok: Buf,
{
    type Item = futures::stream::Iter<std::array::IntoIter<Result<Bytes, S::Error>, 3>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = self.project();
        Poll::Ready(match ready!(this.inner.try_poll_next(cx)) {
            Some(item) => Some(futures::stream::iter(match item {
                Ok(buf) => this.splitter.split(buf).map(Ok),
                Err(err) => [Err(err), Ok(Bytes::new()), Ok(Bytes::new())],
            })),
            None => None,
        })
    }
}

struct AlignedSplitter {
    offset: usize,
    element_size: usize,
}

impl AlignedSplitter {
    fn new(element_size: usize) -> Self {
        assert!(element_size < usize::MAX / 4);
        Self {
            offset: 0,
            element_size,
        }
    }

    fn split(&mut self, mut buf: impl Buf) -> [Bytes; 3] {
        assert!(self.offset < self.element_size);
        let buf_size = buf.remaining();
        let prefix_size = buf.remaining().min(self.element_size - self.offset) % self.element_size;
        let prefix = buf.copy_to_bytes(prefix_size);
        let postfix_size = buf.remaining() % self.element_size;
        let uninterrupted = buf.copy_to_bytes(buf.remaining() - postfix_size);
        let postfix = buf.copy_to_bytes(buf.remaining());
        self.offset = (self.offset + buf_size) % self.element_size;
        [prefix, uninterrupted, postfix]
    }
}

pub(crate) fn buffered<S>(stream: S, chunk_size: usize) -> Buffered<S>
where
    S: TryStream,
    S::Ok: Buf,
{
    assert!(chunk_size > 0);
    Buffered::with_chunk_size(chunk_size, stream)
}

#[pin_project]
pub(crate) struct Buffered<S: TryStream> {
    #[pin]
    inner: S,
    chunk: BytesMut,
    chunk_size: usize,
    queued: std::array::IntoIter<Result<Bytes, S::Error>, 2>,
}

impl<S: TryStream> Buffered<S> {
    pub(crate) fn with_chunk_size(chunk_size: usize, stream: S) -> Self {
        Self {
            inner: stream,
            chunk: BytesMut::with_capacity(2 * chunk_size),
            chunk_size,
            queued: short_iter([]),
        }
    }
}

impl<S> Stream for Buffered<S>
where
    S: TryStream,
    S::Ok: Buf,
{
    type Item = Result<Bytes, S::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        while this.queued.len() == 0 {
            *this.queued = match ready!(this.inner.as_mut().try_poll_next(cx)) {
                Some(Ok(mut data)) => {
                    let remaining_capacity = this.chunk_size.saturating_sub(this.chunk.len());
                    if data.remaining() <= remaining_capacity {
                        this.chunk.put(data);
                        short_iter([])
                    } else if data.remaining() < *this.chunk_size {
                        let chunk = this.chunk.split().freeze();
                        this.chunk.put(data);
                        short_iter([Ok(chunk)])
                    } else if !this.chunk.is_empty() {
                        short_iter([
                            Ok(this.chunk.split().freeze()),
                            Ok(data.copy_to_bytes(data.remaining())),
                        ])
                    } else {
                        short_iter([Ok(data.copy_to_bytes(data.remaining()))])
                    }
                }
                Some(Err(err)) if !this.chunk.is_empty() => {
                    short_iter([Ok(this.chunk.split().freeze()), Err(err)])
                }
                Some(Err(err)) => short_iter([Err(err)]),
                None if !this.chunk.is_empty() => short_iter([Ok(this.chunk.split().freeze())]),
                None => return Poll::Ready(None),
            };
        }
        Poll::Ready(this.queued.next())
    }
}

// Returns 0, 1 or 2 element iter with consistent return type
// ArrayVec isn't feasible because it needs E: Default and doesn't provide ExactSizeIterator
fn short_iter<T: Default, E, const N: usize>(
    vals: [Result<T, E>; N],
) -> std::array::IntoIter<Result<T, E>, 2> {
    let mut results = [Ok(T::default()), Ok(T::default())];
    assert!(vals.len() <= results.len());
    let spare_len = results.len() - vals.len();

    let tail: &mut _ = (&mut results[spare_len..]).try_into().unwrap();
    *tail = vals;

    let mut iter = results.into_iter();
    for _ in 0..spare_len {
        iter.next();
    }
    iter
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::num::NonZeroU16;

    use futures::TryStreamExt;
    use futures::{executor::block_on_stream as stream_to_iter, stream::iter as iter_to_stream};
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct SomeError(i32);

    impl Arbitrary for SomeError {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(Arbitrary::arbitrary(g))
        }
    }

    fn buf_to_vec(mut buf: impl Buf) -> Vec<u8> {
        buf.copy_to_bytes(buf.remaining()).to_vec()
    }

    fn concatenated<S>(stream: S) -> Vec<Result<Vec<u8>, S::Error>>
    where
        S: TryStream + Send + Sync,
        S::Ok: Buf,
    {
        let mut output: Vec<Result<Vec<_>, _>> = vec![];
        for item in stream_to_iter(stream.into_stream().boxed()) {
            match (output.last_mut(), item) {
                (_, Ok(chunk)) if !chunk.has_remaining() => {}
                (Some(Ok(prev_chunk)), Ok(chunk)) => prev_chunk.put(chunk),
                (_, item) => output.push(item.map(buf_to_vec)),
            }
        }
        output
    }

    #[test]
    fn chunking_aligns_chunks() {
        let data = [
            Ok(vec![2, 3, 5, 7]),
            Ok(vec![11, 13]),
            Ok(vec![17, 19, 23]),
            Ok(vec![29, 31, 37, 41]),
            Err(SomeError(42)),
            Err(SomeError(43)),
            Ok(vec![43, 47, 53, 59, 61, 67, 71, 73, 79]),
            Err(SomeError(999)),
        ];

        let bufs = data.into_iter().map(|result| result.map(Cursor::new));
        let stream = iter_to_stream(bufs);

        let element_size = 8;
        let chunked_stream = chunked(stream, element_size);

        let actual: Vec<_> = stream_to_iter(chunked_stream.boxed()).collect();
        let expected = vec![
            Ok(Bytes::from(vec![2, 3, 5, 7, 11, 13, 17, 19])),
            Ok(Bytes::from(vec![23, 29, 31, 37, 41])),
            Err(SomeError(42)),
            Err(SomeError(43)),
            Ok(Bytes::from(vec![43, 47, 53])), // Left over because previous chunk was cut off by error
            Ok(Bytes::from(vec![59, 61, 67, 71, 73, 79])),
            Err(SomeError(999)),
        ];

        assert_eq!(actual, expected);
    }

    #[quickcheck]
    fn chunking_does_not_change_concatenated_data(
        data: Vec<Result<Vec<u8>, SomeError>>,
        element_size: NonZeroU16,
    ) -> bool {
        let bufs = data.into_iter().map(|result| result.map(Cursor::new));
        let stream = iter_to_stream(bufs);
        let chunked_stream = chunked(stream.clone(), element_size.get() as _);

        concatenated(chunked_stream) == concatenated(stream)
    }

    #[quickcheck]
    fn chunking_does_not_produce_empty_buffers(
        data: Vec<Result<Vec<u8>, SomeError>>,
        element_size: NonZeroU16,
    ) -> bool {
        let stream = iter_to_stream(data).map(|result| result.map(Cursor::new));
        let chunked_stream = chunked(stream, element_size.get() as _).boxed();

        stream_to_iter(chunked_stream).all(|chunk| chunk != Ok(Bytes::new()))
    }

    #[quickcheck]
    fn chunking_without_errors_produces_multiples_of_element_size(
        data: Vec<Vec<u8>>,
        element_size: NonZeroU16,
    ) -> bool {
        let stream = iter_to_stream(data).map(|chunk| Result::<_, ()>::Ok(Cursor::new(chunk)));
        let chunked_stream = chunked(stream, element_size.get() as _).boxed();
        let aligned_chunks: Result<Vec<_>, _> = stream_to_iter(chunked_stream).collect();
        let aligned_chunks = aligned_chunks.unwrap();

        if let Some((last, full_chunks)) = aligned_chunks.split_last() {
            let element_size = element_size.get() as usize;
            let full_chunks_are_aligned = full_chunks
                .iter()
                .all(|chunk| chunk.len() % element_size == 0);
            let total_size: usize = aligned_chunks.iter().map(|c| c.len()).sum();
            let last_size_is_correct = last.len() % element_size == total_size % element_size;

            full_chunks_are_aligned && last_size_is_correct
        } else {
            true
        }
    }

    #[test]
    fn buffering_collects_chunks() {
        let data = [
            Ok(vec![2, 3, 5, 7]),
            Ok(vec![11, 13]),
            Ok(vec![17, 19, 23]),
            Ok(vec![29, 31, 37, 41]),
            Err(SomeError(42)),
            Err(SomeError(43)),
            Ok(vec![43, 47, 53, 59, 61, 67, 71, 73, 79]),
            Err(SomeError(999)),
        ];
        let bufs = data.into_iter().map(|result| result.map(Cursor::new));
        let stream = iter_to_stream(bufs);

        let buffer_size = 8;
        let buffered_stream = buffered(stream, buffer_size);

        let actual: Vec<_> = stream_to_iter(buffered_stream).collect();
        let expected = vec![
            Ok(Bytes::from(vec![2, 3, 5, 7, 11, 13])),
            Ok(Bytes::from(vec![17, 19, 23, 29, 31, 37, 41])),
            Err(SomeError(42)),
            Err(SomeError(43)),
            Ok(Bytes::from(vec![43, 47, 53, 59, 61, 67, 71, 73, 79])),
            Err(SomeError(999)),
        ];

        assert_eq!(actual, expected);
    }

    #[quickcheck]
    fn buffering_does_not_change_concatenated_data(
        data: Vec<Result<Vec<u8>, SomeError>>,
        buffer_size: NonZeroU16,
    ) -> bool {
        let bufs = data.into_iter().map(|result| result.map(Cursor::new));
        let stream = iter_to_stream(bufs);
        let buffered_stream = buffered(stream.clone(), buffer_size.get() as _);

        concatenated(buffered_stream) == concatenated(stream)
    }

    #[quickcheck]
    fn buffering_does_not_produce_empty_buffers(
        data: Vec<Result<Vec<u8>, SomeError>>,
        buffer_size: NonZeroU16,
    ) -> bool {
        let stream = iter_to_stream(data).map(|result| result.map(Cursor::new));
        let buffered_stream = buffered(stream, buffer_size.get() as _);

        stream_to_iter(buffered_stream).all(|chunk| chunk != Ok(Bytes::new()))
    }

    #[test]
    fn buffering_passes_single_large_chunk_unchanged() {
        let data = [Result::<_, ()>::Ok([0, 0])];
        let stream = iter_to_stream(data).map(|result| result.map(Cursor::new));

        let buffer_size = 1;
        let buffered_stream = buffered(stream, buffer_size);

        let results: Vec<_> = stream_to_iter(buffered_stream).collect();
        let expected = vec![Result::<_, ()>::Ok(Bytes::from(vec![0, 0]))];
        assert_eq!(results, expected);
    }

    #[quickcheck]
    fn buffering_chooses_chunks_of_appropriate_size(data: Vec<()>) -> bool {
        let size: usize = data.len() * 8;
        let stream = iter_to_stream(data).map(|()| Result::<_, ()>::Ok(Cursor::new([0; 8])));

        let buffer_size = 32;
        let buffered_stream = buffered(stream, buffer_size);

        let chunks: Result<Vec<_>, _> = stream_to_iter(buffered_stream).collect();
        let chunks = chunks.unwrap();

        let full_chunks_are_full = chunks[..size / buffer_size]
            .iter()
            .all(|b| b.len() == buffer_size);
        let partial_chunk_is_correct_size =
            chunks.last().map(|b| b.len()).unwrap_or_default() % buffer_size == size % buffer_size;

        full_chunks_are_full && partial_chunk_is_correct_size
    }

    #[quickcheck]
    fn large_buffers_merge_small_chunks_together(data: Vec<Vec<u8>>) -> bool {
        let concatenated: Vec<_> = data.iter().flatten().copied().collect();
        let stream = iter_to_stream(data).map(|chunk| Result::<_, ()>::Ok(Cursor::new(chunk)));

        let buffer_size = concatenated.len().max(1);
        let buffered_stream = buffered(stream, buffer_size);

        let actual: Result<Vec<_>, _> = stream_to_iter(buffered_stream).collect();
        let mut expected = vec![Bytes::from(concatenated)];
        expected.retain(|b| !b.is_empty());

        actual.unwrap() == expected
    }
}
