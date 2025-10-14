// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end streamed hashing via keyservers
//!
//! [`HashingConfig::hash`] is the main function of interest.

use std::future::Future;
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;
use std::sync::Arc;

use futures::{StreamExt, TryFuture, TryStream, TryStreamExt};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

use doprf::active_security::ActiveSecurityKey;
use doprf::batch::iter::QueryBatches;
use doprf::party::KeyserverId;
use doprf::prf::{CompressedCompletedHashValue, CompressedHashPart, SECURITY_PARAMETER};
use doprf::queryset::QueryError;

use crate::splice::{send_to_keyservers, BatchedQueries, KeyserverError};

/// Errors occuring during initial invocation of [`HashingConfig::hash`]
#[derive(thiserror::Error, Debug)]
pub enum HashingStartupError<E> {
    /// Indicates that the window iterator doesn't have an exact size in practice.
    #[error("unable to determine the number of windows")]
    InexactWindows,
    /// Indicates that there are too many windows to send to keyservers within a single request.
    #[error("sending this would require more queries than can be described in 64 bits")]
    TooManyQueries,
    /// An error was returned by a `keyserver_fn` during startup
    #[error("accessing keyservers")]
    AccessingKeyservers(#[source] E),
}

/// Errors occuring while processing queries
#[derive(thiserror::Error, Debug)]
pub enum HashingStreamError<E> {
    /// An error was returned while receiving hashparts from a keyserver
    #[error("receiving from keyserver")]
    Keyserver(KeyserverError<E>),
    /// Generally indicates that hashparts from keyservers were invalid in some way.
    #[error("encountered problem with hashparts received from keyserver(s): {0:?}")]
    Query(QueryError),
}

/// Configuration for streamed hashing
///
/// This has all the settings that aren't specific to any particular run.
#[derive(Clone, Debug)]
pub struct HashingConfig<E, R> {
    /// The acceptable size range of batches to use when talking with the keyservers.
    ///
    /// Note that this controls the size of the batches sent to the keyservers, *not* the batches
    /// yielded by the [`HashingConfig::hash`].
    pub batch_size: RangeInclusive<usize>,
    /// How many batches may concurrently be executing pre-keyserver crypto.
    ///
    /// Note that whether or not they execute in parallel depends on the
    /// [`executor`](Self::executor). Also, larger numbers result in more memory usage.
    pub pre_keyserver_concurrency: NonZeroUsize,
    /// How many batches the fastest keyserver can get ahead of the slowest one.
    ///
    /// This should probably be at least about 4 (see [`send_to_keyservers`]'s docs on
    /// `max_buffered_batches` for details). Note that it's not an exact limit and larger
    /// numbers result in more memory usage.
    pub keyserver_disparity_cap: NonZeroUsize,
    /// How many batches may concurrently be executing post-keyserver crypto.
    ///
    /// Note that whether or not they execute in parallel depends on the
    /// [`executor`](Self::executor). Also, larger numbers result in more memory usage.
    pub post_keyserver_concurrency: NonZeroUsize,
    /// Verification strength to use.
    ///
    /// See [`doprf::Verifier`] for details.
    pub security_strength: u8,
    /// Customizes how to execute crypto.
    ///
    /// Realistic applications will probably want to use [`LimitedParallelism`].
    pub executor: E,
    /// Cryptographic random number generator used for blinding/verification/etc.
    pub rng: R,
}

impl HashingConfig<NoParallelism, OsRng> {
    /// Supplies reasonable default values for [`HashingConfig`].
    ///
    /// In practice you'll want to set `concurrency` to the number of cores, and pass
    /// [`LimitedParallelism`] to [`HashingConfig::with_executor`].
    pub fn default_for_concurrency(concurrency: NonZeroUsize) -> Self {
        Self {
            batch_size: 100..=1000,
            pre_keyserver_concurrency: concurrency,
            keyserver_disparity_cap: concurrency,
            post_keyserver_concurrency: concurrency,
            security_strength: SECURITY_PARAMETER,
            executor: NoParallelism,
            rng: OsRng,
        }
    }
}

impl<E, R> HashingConfig<E, R> {
    /// Sets the executor if this [`HashingConfig`]
    pub fn with_executor<NewE>(self, executor: NewE) -> HashingConfig<NewE, R> {
        HashingConfig {
            batch_size: self.batch_size,
            pre_keyserver_concurrency: self.pre_keyserver_concurrency,
            keyserver_disparity_cap: self.keyserver_disparity_cap,
            post_keyserver_concurrency: self.post_keyserver_concurrency,
            security_strength: self.security_strength,
            executor,
            rng: self.rng,
        }
    }

    /// Streamed keyserver hashing
    ///
    /// Given an iterators of windows, batches them, blinds them, sends them off to the keyservers
    /// and verifies/recombines the results, yielding [`CompressedCompletedHashValue`]s and
    /// per-window metadata in batches (the completed hashes and metadata are unzipped into two
    /// separate equally-sized [`Vec`]s).
    ///
    /// `windows` is an iterator of `(impl AsRef<[u8]>, M)` pairs (where `M` is custom
    /// per-window metadata that gets passed through untouched). Although `windows` doesn't need
    /// to be an [`ExactSizeIterator`] per se (so it can be chained), it *does* need to have an
    /// exact [`size_hint`](Iterator::size_hint) in practice, as that's used to inform keyservers
    /// about how many queries to expect.
    ///
    /// `keyserver_fns` are used to transform queries into hashparts, presumably communicating
    /// with a keyserver to do so. See [`send_to_keyservers`] for details.
    ///
    /// `active_security_key` is used to verify the results from the `keyserver_fns`.
    pub async fn hash<WI, W, M, KF, Fut, S>(
        &mut self,
        windows: WI,
        keyserver_fns: Vec<(KeyserverId, KF)>,
        active_security_key: Arc<ActiveSecurityKey>,
    ) -> Result<
        impl TryStream<
                Ok = (Vec<CompressedCompletedHashValue>, Vec<M>),
                Error = HashingStreamError<S::Error>,
            > + Send,
        HashingStartupError<Fut::Error>,
    >
    where
        E: Executor + Clone + Send + 'static,
        R: CryptoRng + RngCore,
        WI: IntoIterator<Item = (W, M)>,
        WI::IntoIter: Clone + Send + 'static,
        W: AsRef<[u8]>,
        M: Send + 'static,
        KF: FnOnce(BatchedQueries) -> Fut,
        Fut: TryFuture<Ok = S>,
        S: TryStream<Ok = CompressedHashPart> + Send + Unpin,
        S::Error: Send + 'static,
    {
        // Do basic sanity checking and configure batching...
        let windows = windows.into_iter();
        let (min_windows, max_windows) = windows.size_hint();
        if Some(min_windows) != max_windows {
            return Err(HashingStartupError::InexactWindows);
        }
        let batches = QueryBatches::new(
            &mut self.rng,
            windows,
            self.batch_size.clone(),
            self.security_strength,
            active_security_key.clone(),
        );
        let total_queries = batches
            .remaining_queries()
            .ok_or(HashingStartupError::TooManyQueries)?;
        if total_queries == 0 {
            // Don't bother talking to anything if the stream is empty.
            return Ok(futures::stream::empty().left_stream());
        }
        assert_eq!(active_security_key.supported_quorum(), keyserver_fns.len());

        // Execute pre-keyserver crypto (blinding, etc), possibly in parallel.
        let executor = self.executor.clone();
        let query_batches = futures::stream::iter(batches)
            .map(move |batch_builder| {
                let executor = executor.clone();
                async move { executor.spawn_blocking(|| batch_builder.build()).await }
            })
            .buffered(self.pre_keyserver_concurrency.get());

        // Actually send the blinded queries to the keyservers and get hashparts back
        let buffer_size = self.keyserver_disparity_cap;
        let hashpart_batches =
            send_to_keyservers(total_queries, query_batches, keyserver_fns, buffer_size)
                .await
                .map_err(HashingStartupError::AccessingKeyservers)?;

        // Execute post-keyserver crypto (verification, recombination, etc), possibly in parallel.
        let executor = self.executor.clone();
        let completed_hash_batches = hashpart_batches
            .map_err(HashingStreamError::Keyserver)
            .map_ok(move |(hash_parts, batch_context)| {
                let executor = executor.clone();
                async move {
                    executor
                        .spawn_blocking(move || {
                            batch_context
                                .recombine(&hash_parts)
                                .map_err(HashingStreamError::Query)
                        })
                        .await
                }
            })
            .try_buffered(self.post_keyserver_concurrency.get());

        Ok(completed_hash_batches.right_stream())
    }
}

impl Default for HashingConfig<NoParallelism, OsRng> {
    fn default() -> Self {
        Self::default_for_concurrency(NonZeroUsize::MIN) // 1
    }
}

/// Customizes how [`HashingConfig::hash`] executes expensive operations.
pub trait Executor {
    fn spawn_blocking<F, T>(&self, f: F) -> impl Future<Output = T> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static;
}

/// Executes expensive operations in the same thread immediately.
///
/// This is executor-independent, but probably shouldn't be used for real async applications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoParallelism;

impl Executor for NoParallelism {
    async fn spawn_blocking<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        f()
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod limited_parallelism {
    use std::sync::Arc;

    use tokio::sync::Semaphore;

    use super::Executor;

    /// Executes expensive operations in separate worker threads via [`tokio`].
    #[derive(Clone, Debug)]
    pub struct LimitedParallelism {
        semaphore: Arc<Semaphore>,
    }

    impl LimitedParallelism {
        /// Configure new [`LimitedParallelism`] that uses `semaphore` to limit parallel tasks.
        ///
        /// Each operation will hold a permit from the given `semaphore` for the duration of its
        /// execution.
        pub fn new(semaphore: Arc<Semaphore>) -> Self {
            Self { semaphore }
        }
    }

    impl Executor for LimitedParallelism {
        async fn spawn_blocking<F, T>(&self, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let semaphore = self.semaphore.clone();
            // IMPORTANT: Semaphore is fair, so if we stop having execution assigned to us after
            // we begin waiting for a permit, we can block everyone else from acquiring semaphores,
            // potentially causing a deadlock. To avoid this, we only acquire a permit in a new task,
            // to ensure it WILL get execution assigned to it, eventually preventing deadlock.
            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                tokio::task::spawn_blocking(f).await.unwrap()
            })
            .await
            .unwrap()
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use limited_parallelism::LimitedParallelism;
