// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keyserver stream splicing
//!
//! This module takes a single stream of [`CompressedQuery`] batches, fans it out to multiple
//! keyservers, then brings their output back together. In a picture:
//! ```text
//!                ----> keyserver1 >----
//!               /                      \
//! queries >----+-----> keyserver2 >-----+====> hashparts
//!               \                      /
//!                ----> keyserver3 >----
//! ```
//! Additionally, it splits the response streams into batches matching the size of the input
//! batches, and ensures they get yielded with the correct custom metadata. Note that it
//! ***doesn't*** handle any sort of crypto (such as merging [`CompressedHashPart`] into
//! [`CompressedCompletedHashValue`](doprf::prf::CompressedCompletedHashValue)s), nor does
//! it actually talk to any keyservers (that's the job of the `keyserver_fns`); this *just* does
//! stream wrangling.
//!
//! The primary entrypoint is [`send_to_keyservers`].
use std::fmt;
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use flume::r#async::RecvStream;
use futures::{Stream, StreamExt, TryFuture, TryStream, TryStreamExt};

use doprf::party::KeyserverId;
use doprf::prf::{CompressedHashPart, CompressedQuery};

pub type HashParts = Vec<(KeyserverId, Vec<CompressedHashPart>)>;

/// Errors that occur while [`BatchedHashParts`] attempts to rejoin keyserver responses.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum KeyserverError<E> {
    /// Error in the underlying keyserver response stream, such as disconnection.
    #[error("error receiving response from keyserver {keyserver_id}: {source}")]
    Response {
        keyserver_id: KeyserverId,
        source: E,
    },
    /// A keyserver yielded fewer [`CompressedHashPart`]s than [`CompressedQuery`]s sent to it.
    #[error("keyserver {keyserver_id} response too short")]
    TooShort { keyserver_id: KeyserverId },
    /// A keyserver yielded more [`CompressedHashPart`]s than [`CompressedQuery`]s sent to it.
    #[error("keyserver {keyserver_id} response too long")]
    TooLong { keyserver_id: KeyserverId },
}

/// Describes the streaming behavior of `keyserver_fns`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RequestStreaming {
    /// Assume bidirectional streaming is supported.
    ///
    /// Query metadata is stored using a limited amount of memory, which in turn limits how
    /// many queries a `keyserver_fn` can see before it must start streaming responses back.
    /// This allows processing enormous orders with limited memory, but the `keyserver_fn`s
    /// **MUST NOT** expect all queries up front, or that may cause a deadlock.
    #[default]
    Bidirectional,
    /// Make no assumptions about behavior of HTTP requests.
    ///
    /// Don't place limits on how much query metadata can be stored. This allows non-streaming
    /// `keyserver_fn`s to be used without causing a deadlock, but may cause memory usage
    /// to baloon if there are network problems (or if non-streaming `keyserver_fn`s are used).
    Unspecified,
}

/// Fan out stream of queries to keyservers and recombine responses into a single stream.
///
/// The returned [`BatchedHashParts`] is a stream of pairs, each containing a [`HashParts`] and
/// custom metadata. Assuming no errors occur, one pair is is returned per item of
/// `batched_queries` in the same order. Any errors in `keyserver_fns` (or their returned
/// streams) are propagated. Additionally the returned [`BatchedHashParts`] will yield an
/// error if it detects that any keyserver response stream doesn't yield the same number of
/// hash parts as queries that were sent to it.
///
/// `batched_queries` is a stream of batches, where each batch consists of query data and
/// custom metadata of type `M`.
///
/// `keyserver_fns` are the functions actually responsible for transforming a [`BatchedQueries`]
/// into a `impl TryStream<Ok=CompressedHashPart>`. One should be provided for each keyserver.
/// Note that although [`send_to_keyservers`] returns a stream of batches, it expects the
/// keyserver functions to return a stream of individual [`CompressedHashPart`]s back from the
/// keyserver. In other words, each keyserver function should have the signature:
/// `async fn(BatchedQueries) -> Result<impl TryStream<Ok=CompressedHashPart, RE>, SE>`
/// where `SE` is a setup error (e.g. server rejected authentication) and `RE` is a response
/// error (e.g. connection severed mid-stream).
///
/// `total_queries` is the total number of queries across all batches of `batched_queries`.
/// It's propagated to [`BatchedQueries::remaining_queries`] so the keyserver functions can
/// inform the remote server of the expected size. It is considered a programming error for this
/// to be inaccurate; that may result in a panic.
///
/// `max_buffered_batches` tunes how many batches should be queued up and ready to send to
/// the keyservers at any given time. While any valid number should work, small numbers may
/// cause unnecessary bottlenecks by forcing all transfers to/from keyservers to be in lockstep
/// with one another, magnifying delays. This should be *at least* 4, though higher numbers will
/// provide more resilience to temporary variations in keyserver speed (at the cost of more
/// memory usage). With a `max_buffered_batches` of 4, you can have (in parallel):
/// * A batch being transferred *to* the keyservers
/// * A batch being processed by the keyservers
/// * A batch being transferred *from* the keyservers
/// * At least one spare batch in case a keyserver gets slightly ahead of the others.
pub async fn send_to_keyservers<Q, M, F, Fut, HP, SE, RE>(
    total_queries: u64,
    batched_queries: Q,
    keyserver_fns: Vec<(KeyserverId, F)>,
    keyserver_fn_streaming: RequestStreaming,
    max_buffered_batches: NonZeroUsize,
) -> Result<BatchedHashParts<M, HP>, SE>
where
    Q: Stream<Item = (Arc<[CompressedQuery]>, M)> + Send + 'static,
    M: Send + 'static,
    F: FnOnce(BatchedQueries) -> Fut,
    Fut: TryFuture<Ok = HP, Error = SE>,
    HP: TryStream<Ok = CompressedHashPart, Error = RE> + Unpin,
{
    let (metadata_sender, metadata_receiver) = match keyserver_fn_streaming {
        RequestStreaming::Bidirectional => flume::bounded(max_buffered_batches.get()),
        RequestStreaming::Unspecified => flume::unbounded(),
    };
    let ((senders, ks_ids), futures): (_, Vec<_>) = keyserver_fns
        .into_iter()
        .map(|(ks_id, keyserver_fn)| {
            let (sender, receiver) = flume::bounded(max_buffered_batches.get());
            let batched_queries = BatchedQueries {
                remaining_queries: total_queries,
                receiver: receiver.into_stream(),
            };
            let future = keyserver_fn(batched_queries);
            ((sender, ks_id), future)
        })
        .unzip();

    let mut pump = Box::pin(pump_input(
        total_queries,
        batched_queries,
        senders,
        metadata_sender,
    ));
    // NOTE: We must run the pump concurrently with the keyserver function futures,
    // in case one (*cough*unit-tests*cough*) collects queries upfront. (but has large queues)
    let output_streams = tokio::select! {
        biased; // biased so we don't pump if the futures are instantaneous
        output_streams = futures::future::try_join_all(futures) => output_streams?,
        () = &mut pump => unreachable!(),
    };

    Ok(BatchedHashParts::new(
        pump,
        metadata_receiver,
        ks_ids,
        output_streams,
    ))
}

// Pulls from `batches`, sending queries to keyserver queues and metadata to `BatchedQueries`
// Note that this never resolves, ensuring it's always ok to poll.
async fn pump_input<M>(
    total_queries: u64,
    batches: impl Stream<Item = (Arc<[CompressedQuery]>, M)>,
    senders: Vec<flume::Sender<Arc<[CompressedQuery]>>>,
    metadata_sender: flume::Sender<BatchMetadata<M>>,
) {
    let mut remaining_queries = total_queries;
    let mut batches = pin!(batches);
    while let Some((batch, custom_metadata)) = batches.next().await {
        let batch_len = batch.len().try_into().ok();
        remaining_queries = batch_len
            .and_then(|batch_len| remaining_queries.checked_sub(batch_len))
            .expect("BUG: Sent more queries than declared.");

        // An error here can only happen if this module is buggy...
        let metadata = BatchMetadata {
            batch_len: batch.len(),
            custom_metadata,
        };
        metadata_sender
            .send_async(metadata)
            .await
            .expect("BUG: metadata channel closed too early.");
        for sender in &senders {
            // Errors are fine here: The keyserver_fn must have dropped the BatchedQueries.
            // Presumably it might have done that as part of cleanup before returning an error?
            let _ = sender.send_async(batch.clone()).await;
        }
    }
    assert_eq!(
        remaining_queries, 0,
        "BUG: Sent fewer queries than declared."
    );
    // Drop senders to ensure all queues can detect when they've exhausted their data.
    drop(metadata_sender);
    drop(senders);
    std::future::pending().await
}

/// Stream of `Arc<[CompressedQuery]>`s to be sent to a keyserver.
///
/// NOTE: This is fed by a [`BatchedHashParts`] and may hang if that's dropped or otherwise
/// not being executed.
#[pin_project::pin_project]
pub struct BatchedQueries {
    remaining_queries: u64,
    #[pin]
    receiver: RecvStream<'static, Arc<[CompressedQuery]>>,
}

impl BatchedQueries {
    /// Returns the total number of queries across all batches that haven't yet been yielded.
    pub fn remaining_queries(&self) -> u64 {
        self.remaining_queries
    }
}

impl Stream for BatchedQueries {
    type Item = Arc<[CompressedQuery]>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let result = this.receiver.poll_next(cx);
        match result {
            // pump_input has already checked that this math should succeed; if not,
            // it would have panicked, complaining about sending more queries than declared
            Poll::Ready(Some(ref batch)) => *this.remaining_queries -= batch.len() as u64,
            // There are two ways for this branch to happen:
            // 1) Too few queries were sent, in which case pump_input should have panicked,
            // and hopefully we can count on the hashparts stream getting dropped soon.
            // 2) The hashparts stream was canceled (dropped before completion), presumably
            // due to an error occuring elsewhere (such as HDB auth rejection).
            // Either way, the keyserver fns should get dropped, so we don't need to terminate
            // the stream. Just hang and give everything else a chance to sort itself out.
            Poll::Ready(None) if *this.remaining_queries != 0 => return Poll::Pending,
            _ => {}
        }
        result
    }
}

impl fmt::Debug for BatchedQueries {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BatchedQueries").finish_non_exhaustive()
    }
}

struct BatchMetadata<T> {
    batch_len: usize,
    custom_metadata: T,
}

/// Stream of [`HashParts`] and per-batch metadata returned from [`send_to_keyservers`].
#[pin_project::pin_project]
pub struct BatchedHashParts<M: 'static, S> {
    /// Shuffles data from our input stream to the keyservers and `metadata_receiver`.
    pump_input: Pin<Box<dyn Future<Output = ()> + Send>>,
    /// Tells us what size batch to expect next.
    #[pin]
    metadata_receiver: RecvStream<'static, BatchMetadata<M>>,
    /// Which keyserver the corresponding index in `output_streams` goes to.
    keyserver_ids: Vec<KeyserverId>,
    /// HashPart streams returning from keyservers to us.
    output_streams: Vec<S>,
    /// The current batch we're operating on
    metadata: Option<BatchMetadata<M>>,
    /// The hashparts from all keyservers; this is either empty or partial
    hash_parts: HashParts,
    /// True iff this stream has ended, either due to exhaustion or error.
    is_terminated: bool,
}

impl<M, S> BatchedHashParts<M, S> {
    fn new(
        pump_input: Pin<Box<dyn Future<Output = ()> + Send>>,
        metadata_receiver: flume::Receiver<BatchMetadata<M>>,
        keyserver_ids: Vec<KeyserverId>, // Not using KeyserverIdSet because order matters
        output_streams: Vec<S>,
    ) -> Self {
        Self {
            pump_input,
            metadata_receiver: metadata_receiver.into_stream(),
            keyserver_ids,
            output_streams,
            metadata: None,
            hash_parts: vec![],
            is_terminated: false,
        }
    }

    // Yields an error if any output_streams have more data.
    // Returns Poll::Ready(None) if all output_streams have terminated.
    // Otherwise, returns Poll::Pending and prunes output_streams/keyserver_ids that have ended.
    fn ensure_all_streams_have_ended<T, E>(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<T, KeyserverError<E>>>>
    where
        S: TryStream<Error = E> + Unpin,
    {
        if let Some((ks_id, _)) = self.hash_parts.iter().find(|(_, hp)| !hp.is_empty()) {
            let keyserver_id = *ks_id;
            self.terminate();
            return Poll::Ready(Some(Err(KeyserverError::TooLong { keyserver_id })));
        }
        for i in (0..self.output_streams.len()).rev() {
            match self.output_streams[i].try_poll_next_unpin(cx) {
                Poll::Ready(Some(Err(source))) => {
                    let keyserver_id = self.keyserver_ids[i];
                    self.terminate();
                    return Poll::Ready(Some(Err(KeyserverError::Response {
                        keyserver_id,
                        source,
                    })));
                }
                Poll::Ready(Some(Ok(_))) => {
                    let keyserver_id = self.keyserver_ids[i];
                    self.terminate();
                    return Poll::Ready(Some(Err(KeyserverError::TooLong { keyserver_id })));
                }
                Poll::Ready(None) => {
                    self.output_streams.swap_remove(i);
                    self.keyserver_ids.swap_remove(i);
                }
                Poll::Pending => {}
            }
        }
        if self.output_streams.is_empty() {
            self.terminate();
            return Poll::Ready(None);
        }
        Poll::Pending
    }

    fn terminate(self: Pin<&mut Self>) {
        let this = self.project();

        *this.is_terminated = true;
        *this.keyserver_ids = vec![];
        *this.output_streams = vec![];
        *this.metadata = None;
        *this.hash_parts = vec![];
    }
}

impl<M, S> Stream for BatchedHashParts<M, S>
where
    S: TryStream<Ok = CompressedHashPart> + Unpin,
{
    type Item = Result<(HashParts, M), KeyserverError<S::Error>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().project();

        if *this.is_terminated {
            return Poll::Ready(None);
        }

        let _ = this.pump_input.as_mut().poll(cx);

        // Make sure we have a batch (size, etc) to operate on.
        let metadata = match this.metadata {
            Some(metadata) => metadata,
            None => {
                let Some(metadata) = ready!(this.metadata_receiver.poll_next(cx)) else {
                    // Ok, we've gotten to the end of the metadata stream...
                    // Double-check that all keyserver streams have finished up too.
                    // No big deal if this is Pending; if so, we should end up here again.
                    return self.ensure_all_streams_have_ended(cx);
                };
                // Starting a new HashParts...
                *this.hash_parts = (this.keyserver_ids.iter())
                    .map(|&ks_id| (ks_id, Vec::with_capacity(metadata.batch_len)))
                    .collect();
                this.metadata.insert(metadata)
            }
        };

        let mut is_complete = true;
        for ((keyserver_id, ks_hash_parts), ks_output_stream) in
            this.hash_parts.iter_mut().zip(this.output_streams)
        {
            let keyserver_id = *keyserver_id;
            while ks_hash_parts.len() < metadata.batch_len {
                match ks_output_stream.try_poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(hash_part))) => ks_hash_parts.push(hash_part),
                    Poll::Ready(Some(Err(err))) => {
                        self.terminate();
                        return Poll::Ready(Some(Err(KeyserverError::Response {
                            keyserver_id,
                            source: err,
                        })));
                    }
                    Poll::Ready(None) => {
                        self.terminate();
                        return Poll::Ready(Some(Err(KeyserverError::TooShort { keyserver_id })));
                    }
                    Poll::Pending => {
                        is_complete = false;
                        break;
                    }
                }
            }
        }
        if !is_complete {
            return Poll::Pending;
        }

        let metadata = this
            .metadata
            .take()
            .expect("BUG: previously checked metadata is Some, yet it's None");
        let hash_parts = std::mem::take(this.hash_parts);
        Poll::Ready(Some(Ok((hash_parts, metadata.custom_metadata))))
    }
}

impl<M, S> fmt::Debug for BatchedHashParts<M, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BatchedHashParts").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::fmt::Display;
    use std::io::{Cursor, Write};
    use std::sync::Mutex;

    use futures::FutureExt;

    // The splice module doesn't actually do any crypto or even care whether keyservers
    // are handing it garbage; its job is just to collate the data and pass it on.
    // To save computation and improve debuggability, we make dummy values from strings.
    fn dummy<T: From<[u8; 32]>>(description: impl Display) -> T {
        let mut buf = Cursor::new([b' '; 32]);
        write!(buf, "{description}").expect("description couldn't fit");
        buf.into_inner().into()
    }

    fn keyserver_id(id: u32) -> KeyserverId {
        id.try_into().unwrap()
    }

    #[tokio::test]
    async fn smoke_test() {
        let query_batches = futures::stream::iter([
            (
                Arc::from_iter([dummy("query1"), dummy("query2")]),
                "batch1 metadata",
            ),
            (Arc::from_iter([dummy("query3")]), "batch2 metadata"),
            (Arc::from_iter([]), "batch3 metadata"),
            (
                Arc::from_iter([dummy("query4"), dummy("query5"), dummy("query6")]),
                "batch4 metadata",
            ),
        ]);
        let total_queries = 6;

        let keyserver_fns = [2, 3, 5]
            .map(|ks_id| {
                let keyserve = move |batched_queries: BatchedQueries| async move {
                    assert_eq!(batched_queries.remaining_queries(), 6);
                    let queries: Vec<_> = batched_queries.collect().await;
                    let expected_queries = [
                        Arc::from_iter([dummy("query1"), dummy("query2")]),
                        Arc::from_iter([dummy("query3")]),
                        Arc::from_iter([]),
                        Arc::from_iter([dummy("query4"), dummy("query5"), dummy("query6")]),
                    ];
                    assert_eq!(
                        queries, expected_queries,
                        "keyserver {ks_id} got wrong query batches"
                    );

                    let hashparts = (1..=total_queries).map(move |h_id| {
                        let hashpart = dummy(format_args!("keyserver {ks_id} hashpart {h_id}"));
                        Ok::<_, Infallible>(hashpart)
                    });
                    Ok::<_, Infallible>(futures::stream::iter(hashparts))
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        let max_buffered_batches = 4.try_into().unwrap();
        let Ok(hashparts) = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await;

        // Note that the hashparts are grouped into batches of the same size as the original
        // query batches.
        let hashparts: Vec<_> = hashparts.try_collect().await.unwrap();
        let expected = [
            (
                vec![
                    (
                        keyserver_id(2),
                        vec![
                            dummy("keyserver 2 hashpart 1"),
                            dummy("keyserver 2 hashpart 2"),
                        ],
                    ),
                    (
                        keyserver_id(3),
                        vec![
                            dummy("keyserver 3 hashpart 1"),
                            dummy("keyserver 3 hashpart 2"),
                        ],
                    ),
                    (
                        keyserver_id(5),
                        vec![
                            dummy("keyserver 5 hashpart 1"),
                            dummy("keyserver 5 hashpart 2"),
                        ],
                    ),
                ],
                "batch1 metadata",
            ),
            (
                vec![
                    (keyserver_id(2), vec![dummy("keyserver 2 hashpart 3")]),
                    (keyserver_id(3), vec![dummy("keyserver 3 hashpart 3")]),
                    (keyserver_id(5), vec![dummy("keyserver 5 hashpart 3")]),
                ],
                "batch2 metadata",
            ),
            (
                vec![
                    (keyserver_id(2), vec![]),
                    (keyserver_id(3), vec![]),
                    (keyserver_id(5), vec![]),
                ],
                "batch3 metadata",
            ),
            (
                vec![
                    (
                        keyserver_id(2),
                        vec![
                            dummy("keyserver 2 hashpart 4"),
                            dummy("keyserver 2 hashpart 5"),
                            dummy("keyserver 2 hashpart 6"),
                        ],
                    ),
                    (
                        keyserver_id(3),
                        vec![
                            dummy("keyserver 3 hashpart 4"),
                            dummy("keyserver 3 hashpart 5"),
                            dummy("keyserver 3 hashpart 6"),
                        ],
                    ),
                    (
                        keyserver_id(5),
                        vec![
                            dummy("keyserver 5 hashpart 4"),
                            dummy("keyserver 5 hashpart 5"),
                            dummy("keyserver 5 hashpart 6"),
                        ],
                    ),
                ],
                "batch4 metadata",
            ),
        ];
        assert_eq!(hashparts, expected);
    }

    #[tokio::test]
    async fn keyserver_fn_errors_are_propagated() {
        let query_batches =
            futures::stream::iter([(Arc::from_iter([dummy("query"); 2]), "metadata")]);
        let total_queries = 2;

        #[derive(Debug, PartialEq, Eq)]
        struct KsFnErr(u8);

        let keyserver_fns = [2, 3, 5]
            .map(|ks_id| {
                let keyserve = move |_batched_queries| async move {
                    if ks_id == 3 {
                        return Err(KsFnErr(123));
                    }
                    let hashparts = [Ok::<_, Infallible>(dummy("hashpart")); 2];
                    Ok(futures::stream::iter(hashparts))
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        let max_buffered_batches = 1.try_into().unwrap();
        let err = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await
        .unwrap_err();

        assert_eq!(err, KsFnErr(123));
    }

    #[tokio::test]
    async fn keyserver_fn_stream_errors_are_propagated() {
        let query_batches = futures::stream::iter([
            (Arc::from_iter([dummy("query"); 2]), "batch1 metadata"),
            (Arc::from_iter([dummy("query"); 3]), "batch2 metadata"),
            (Arc::from_iter([dummy("query"); 1]), "batch3 metadata"),
        ]);
        let total_queries = 6;

        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        struct KsStreamErr(u8);

        let keyserver_fns = [2, 3, 5]
            .map(|ks_id| {
                let keyserve = move |_batched_queries| async move {
                    let hashparts = if ks_id == 3 {
                        vec![
                            Ok(dummy("hashpart")),
                            Ok(dummy("hashpart")),
                            Ok(dummy("hashpart")),
                            Err(KsStreamErr(123)),
                        ]
                    } else {
                        vec![Ok(dummy("hashpart")); total_queries as usize]
                    };
                    Ok::<_, Infallible>(futures::stream::iter(hashparts))
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        let max_buffered_batches = 1.try_into().unwrap();
        let Ok(hashparts) = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await;

        let hashparts: Vec<_> = hashparts.collect().await;
        let expected = [
            Ok((
                vec![
                    (keyserver_id(2), vec![dummy("hashpart"); 2]),
                    (keyserver_id(3), vec![dummy("hashpart"); 2]),
                    (keyserver_id(5), vec![dummy("hashpart"); 2]),
                ],
                "batch1 metadata",
            )),
            Err(KeyserverError::Response {
                keyserver_id: keyserver_id(3),
                source: KsStreamErr(123),
            }),
        ];
        assert_eq!(hashparts, expected);
    }

    #[tokio::test]
    async fn truncated_streams_are_detected() {
        let query_batches = futures::stream::iter([
            (Arc::from_iter([dummy("query"); 2]), "batch1 metadata"),
            (Arc::from_iter([dummy("query"); 1]), "batch2 metadata"),
            (Arc::from_iter([dummy("query"); 3]), "batch3 metadata"),
        ]);
        let total_queries = 6;

        let keyserver_fns = [2, 3, 5]
            .map(|ks_id| {
                let keyserve = move |_batched_queries| async move {
                    let mut hashparts =
                        vec![Ok::<_, Infallible>(dummy("hashpart")); total_queries as usize];
                    if ks_id == 3 {
                        hashparts.pop();
                    }
                    Ok::<_, Infallible>(futures::stream::iter(hashparts))
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        let max_buffered_batches = 1.try_into().unwrap();
        let Ok(hashparts) = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await;

        let hashparts: Vec<_> = hashparts.collect().await;
        let expected = [
            Ok((
                vec![
                    (keyserver_id(2), vec![dummy("hashpart"); 2]),
                    (keyserver_id(3), vec![dummy("hashpart"); 2]),
                    (keyserver_id(5), vec![dummy("hashpart"); 2]),
                ],
                "batch1 metadata",
            )),
            Ok((
                vec![
                    (keyserver_id(2), vec![dummy("hashpart"); 1]),
                    (keyserver_id(3), vec![dummy("hashpart"); 1]),
                    (keyserver_id(5), vec![dummy("hashpart"); 1]),
                ],
                "batch2 metadata",
            )),
            Err(KeyserverError::TooShort {
                keyserver_id: keyserver_id(3),
            }),
        ];
        assert_eq!(hashparts, expected);
    }

    #[tokio::test]
    async fn bonus_hashparts_are_detected() {
        let query_batches = futures::stream::iter([
            (Arc::from_iter([dummy("query"); 2]), "batch1 metadata"),
            (Arc::from_iter([dummy("query"); 1]), "batch2 metadata"),
            (Arc::from_iter([dummy("query"); 3]), "batch3 metadata"),
        ]);
        let total_queries = 6;

        let keyserver_fns = [2, 3, 5]
            .map(|ks_id| {
                let keyserve = move |_batched_queries| async move {
                    let mut hashparts =
                        vec![Ok::<_, Infallible>(dummy("hashpart")); total_queries as usize];
                    if ks_id == 3 {
                        hashparts.push(Ok(dummy("hashpart")));
                    }
                    Ok::<_, Infallible>(futures::stream::iter(hashparts))
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        let max_buffered_batches = 1.try_into().unwrap();
        let Ok(hashparts) = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await;

        let hashparts: Vec<_> = hashparts.collect().await;
        let expected = [
            Ok((
                vec![
                    (keyserver_id(2), vec![dummy("hashpart"); 2]),
                    (keyserver_id(3), vec![dummy("hashpart"); 2]),
                    (keyserver_id(5), vec![dummy("hashpart"); 2]),
                ],
                "batch1 metadata",
            )),
            Ok((
                vec![
                    (keyserver_id(2), vec![dummy("hashpart"); 1]),
                    (keyserver_id(3), vec![dummy("hashpart"); 1]),
                    (keyserver_id(5), vec![dummy("hashpart"); 1]),
                ],
                "batch2 metadata",
            )),
            Ok((
                vec![
                    (keyserver_id(2), vec![dummy("hashpart"); 3]),
                    (keyserver_id(3), vec![dummy("hashpart"); 3]),
                    (keyserver_id(5), vec![dummy("hashpart"); 3]),
                ],
                "batch3 metadata",
            )),
            Err(KeyserverError::TooLong {
                keyserver_id: keyserver_id(3),
            }),
        ];
        assert_eq!(hashparts, expected);
    }

    #[tokio::test]
    async fn max_buffered_batches_limits_concurrency() {
        let query_batches = futures::stream::iter([
            (Arc::from_iter([dummy("query"); 2]), "batch1 metadata"),
            (Arc::from_iter([dummy("query"); 1]), "batch2 metadata"),
            (Arc::from_iter([]), "batch3 metadata"),
            (Arc::from_iter([dummy("query"); 3]), "batch4 metadata"),
        ]);
        let total_queries = 6;

        let query_batches_read = Arc::new(Mutex::new(0));
        let counter = query_batches_read.clone();
        let query_batches = query_batches.inspect(move |_| {
            *counter.lock().unwrap() += 1;
        });

        let (throttles, keyserver_fns): (Vec<_>, Vec<_>) = [1, 2, 3]
            .into_iter()
            .map(|ks_id| {
                let (throttle_tx, throttle_rx) = flume::bounded::<()>(4);
                let throttle = throttle_rx.into_stream();

                let keyserve = move |batched_queries: BatchedQueries| async move {
                    // Ensure we read from the batches when a keyserver really would.
                    let flattened_queries =
                        batched_queries.flat_map(|batch| futures::stream::iter(0..batch.len()));
                    // Use throttle to control when this reads from batched_queries and produces
                    // hashparts.
                    let hashparts = throttle
                        .zip(flattened_queries)
                        .map(|_| Ok::<_, Infallible>(dummy("hashpart")));
                    Ok::<_, Infallible>(hashparts)
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (throttle_tx, (ks_id, keyserve))
            })
            .collect();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        // Unrealistally low, but makes it easier to predict how things should behave.
        let max_buffered_batches = 1.try_into().unwrap();

        let Ok(mut hashparts) = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await;

        // We haven't pulled from the `BatchedHashParts` yet and our keyserver functions
        // haven't inspected the input stream, so the input stream should be untouched.
        assert_eq!(*query_batches_read.lock().unwrap(), 0);
        // We haven't granted any "keyservers" permission to return any hashparts,
        // so there's no batch to return.
        assert!(hashparts.next().now_or_never().is_none());

        // Tell keyserver1 (KS1) to process one hash and KS2/3 to process a couple each.
        for ks in [0, 1, 1, 2, 2] {
            throttles[ks].send_async(()).await.unwrap();
        }
        // After this, the way things should look is:
        // (Q = query, H = processed hashpart, B# = batch, KS# = keyserver)
        //     B1 B2 B3 B4
        // KS1 HQ Q     QQQ
        // KS2 HH Q     QQQ
        // KS3 HH Q     QQQ
        // ...so the first batch is missing a hashpart from KS1, so we won't get anything back:
        assert!(hashparts.next().now_or_never().is_none());
        // Likewise, we've probably read 3 batches of queries from the input at this point;
        // the first one is being processed by the keyservers, the second is sitting in the
        // queues waiting for keyservers to accept it, and the third is waiting around in
        // `pump_input` for the queues get spare space.
        let input_batches_read = *query_batches_read.lock().unwrap();
        assert!(input_batches_read > 0); // Regardles of impl, we must have read at least one
        assert!(input_batches_read < 4); // ...but not all batches due to queue size of 1.

        for ks in [0, 0, 0, 0, 1, 1, 1, 1, 2] {
            throttles[ks].send_async(()).await.unwrap();
        }
        // Ok, now things should look like:
        //     B1 B2 B3 B4
        // KS1 HH H     HHQ
        // KS2 HH H     HHH
        // KS3 HH H     QQQ
        // Batches B1, B2 and B3 should now be ready:
        hashparts.next().now_or_never().unwrap().unwrap().unwrap();
        hashparts.next().now_or_never().unwrap().unwrap().unwrap();
        hashparts.next().now_or_never().unwrap().unwrap().unwrap();
        // ...but not B4:
        assert!(hashparts.next().now_or_never().is_none());
        // And we've presumably read all input now.
        assert_eq!(*query_batches_read.lock().unwrap(), 4);

        for ks in [0, 2, 2, 2] {
            throttles[ks].send_async(()).await.unwrap();
        }
        // Ok, now things should look like:
        //     B1 B2 B3 B4
        // KS1 HH H     HHH
        // KS2 HH H     HHH
        // KS3 HH H     HHH
        // So batch B4 is now done:
        hashparts.next().now_or_never().unwrap().unwrap().unwrap();

        // ...and the stream is exhausted
        assert!(hashparts.next().now_or_never().unwrap().is_none());
    }

    #[tokio::test]
    #[should_panic]
    async fn missing_queries_are_detected() {
        let query_batches =
            futures::stream::iter([(Arc::from_iter([dummy("query"); 2]), "metadata")]);
        let total_queries = 3;

        let keyserver_fns = [2, 3, 5]
            .map(|ks_id| {
                let keyserve = async move |mut batched_queries: BatchedQueries| {
                    while batched_queries.next().await.is_some() {}
                    let stream =
                        futures::stream::pending::<Result<CompressedHashPart, Infallible>>();
                    Ok::<_, Infallible>(stream)
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        let max_buffered_batches = 5.try_into().unwrap();
        let _ = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn extra_queries_are_detected() {
        let query_batches =
            futures::stream::iter([(Arc::from_iter([dummy("query"); 3]), "metadata")]);
        let total_queries = 2;

        let keyserver_fns = [2, 3, 5]
            .map(|ks_id| {
                let keyserve = async move |mut batched_queries: BatchedQueries| {
                    while batched_queries.next().await.is_some() {}
                    let stream =
                        futures::stream::pending::<Result<CompressedHashPart, Infallible>>();
                    Ok::<_, Infallible>(stream)
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        let max_buffered_batches = 5.try_into().unwrap();
        let _ = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await;
    }

    #[tokio::test]
    async fn dropping_hashparts_stream_doesnt_trigger_false_alarm() {
        let query_batches = futures::stream::pending::<(Arc<[CompressedQuery]>, ())>();
        let total_queries = 5;

        let (query_batches_tx, query_batches_rx) = flume::bounded(4);

        let keyserver_fns = [2, 3, 5]
            .map(move |ks_id| {
                let query_batches_tx = query_batches_tx.clone();
                let keyserve = async move |batched_queries: BatchedQueries| {
                    query_batches_tx.send_async(batched_queries).await.unwrap();
                    let stream =
                        futures::stream::pending::<Result<CompressedHashPart, Infallible>>();
                    Ok::<_, Infallible>(stream)
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        let keyserver_fn_streaming = RequestStreaming::Bidirectional;
        let max_buffered_batches = 5.try_into().unwrap();
        let hashparts = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await
        .unwrap();

        // If hashparts is dropped due to everything getting canceled (e.g. due to HDB auth
        // failure), we DON'T want to trigger the "sent fewer queries than declared" panic.
        drop(hashparts);
        for _ in 0..3 {
            let mut batches = query_batches_rx.recv_async().await.unwrap();
            assert!(batches.next().now_or_never().is_none());
        }
    }

    #[tokio::test]
    async fn unknown_streaming_doesnt_limit_batches() {
        let query_batches = futures::stream::iter([
            (Arc::from_iter([dummy("query"); 1]), "metadata"),
            (Arc::from_iter([dummy("query"); 1]), "metadata"),
        ]);
        let total_queries = 2;

        let keyserver_fns = [2, 3, 5]
            .map(|ks_id| {
                let keyserve = async move |mut batched_queries: BatchedQueries| {
                    // consume entire request before returning response
                    while batched_queries.next().await.is_some() {}

                    let stream =
                        futures::stream::pending::<Result<CompressedHashPart, Infallible>>();
                    Ok::<_, Infallible>(stream)
                };
                let ks_id = KeyserverId::try_from(ks_id).unwrap();
                (ks_id, keyserve)
            })
            .to_vec();

        // We set `max_buffered_batches` lower than the total number of batches (2),
        // so when the `keyserver_fn` tries to consume the entire request, it'll blow
        // past the `max_buffered_batches` limit... if we used `RequestStreaming::Bidirectional`
        // the splicing code would refuse to hand over more of the request to the `keyserver_fns`
        // until they started streaming stuff back, but the `keyserver_fns` don't stream so
        // that'd lead to a deadlock. This comes up in the WASM environment where some browsers
        // don't support bidirectional streaming, so we need to be able to disable just the
        // metadata limits.
        // TL;DR: This test should hang if `RequestStreaming::Bidirectional` is used,
        // but not if `RequestStreaming::Unspecified` is used.
        let keyserver_fn_streaming = RequestStreaming::Unspecified;
        let max_buffered_batches = 1.try_into().unwrap();
        let _ = send_to_keyservers(
            total_queries,
            query_batches,
            keyserver_fns,
            keyserver_fn_streaming,
            max_buffered_batches,
        )
        .await;
    }
}
