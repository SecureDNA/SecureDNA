// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batching iterator for windows, handling crypto. See [`QueryBatches`].

use std::ops::RangeInclusive;
use std::sync::Arc;

use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};

use crate::active_security::ActiveSecurityKey;
use crate::party::KeyserverId;
use crate::prf::{CompressedCompletedHashValue, CompressedHashPart, CompressedQuery};
use crate::queryset::{setup_queries, QueriesSecurityContext, QueryError};

use super::layout::{BatchLayout, BatchLayouts};

// Skipping support for fallible window iterators for now... can always add it later if needed.

/// Applies batching and queryset crypto to a window iterator.
///
/// Given an iterable of `(window, custom metadata)` pairs, this chunks it into batches,
/// yielding a [`BatchBuilder`] for each batch. [`BatchBuilder::build`] does all the actual
/// expensive work of setting up the batch, returning an [`Arc<CompressedQuery>`] and
/// [`BatchContext`]. [`BatchContext::recombine`] can then validate and merge keyserver
/// responses, returning the final [`Vec<CompressedCompletedHashValue>`] and
/// [`Vec<custom metadata>`].
///
/// # Performance characteristics (IMPORTANT!)
///
/// Note that [`QueryBatches`] doesn't populate batches while iterating; rather, it forks off
/// a copy of the window iterator into the [`BatchBuilder`], then fast-forwards the window
/// iterator past the batch. The hope is that (depending on the window iterator) this can
/// potentially minimize the amount of work a central manager thread has to do to iterate over
/// batches, allowing for more parallelization of [`BatchBuilder::build`] and
/// [`BatchContext::recombine`].
///
/// However, this means it's important for the window iterator to be (somewhat) cheaply clonable,
/// both CPU and memory-wise. Ideally, cloning should be constant-time relative to the size
/// of the input sequences and any potentially large buffers should be shared between clones.
///
/// Another downside of this approach is that the work of iterating through windows potentially
/// happens twice: Once by the [`QueryBatches`] fast-forwarding through batches, and once by the
/// individual [`BatchBuilder`]s populating their queries. On the bright side, our current window
/// iterators are relatively cheap, and adding special support for [`Iterator::nth`] could make
/// the fast-forwarding even cheaper.
///
/// # Custom metadata
///
/// This can be used to pass arbitrary per-window information through the [`QueryBatches`].
/// Generally it's used to track what kind of window each hash was generated from.
///
/// Note that it gets unzipped from the windows and returned as a separate [`Vec`], per batch.
///
/// # Why can't this be cloned?
///
/// This uses a CSPRNG for padding, blinding and verification. The obvious ways of implementing
/// cloning would make it easy to accidentally subvert security by reusing the same values.
/// Since that would be difficult to notice, it's probably better not to provide such an API.
/// If need be, we could make a custom `clone` method that takes an RNG state to reseed off of.
pub struct QueryBatches<WI> {
    rng: StdRng,
    windows: WI,
    layouts: BatchLayouts,
    security_strength: u8,
    active_security_key: Arc<ActiveSecurityKey>,
}

impl<WI> QueryBatches<WI> {
    /// Create new [`QueryBatches`] from a window iterator.
    ///
    /// `windows` is a sequence of `(window, metadata)` pairs.
    ///
    /// `batch_len` is the range of possible sizes that batches are allowed to be.
    /// It is a programming error for the minimum or maximum size to be 0.
    ///
    /// `security_strength` tunes verification. See [`Verifier`](crate::Verifier) for details.
    ///
    /// `active_security_key` is used for verification of keyserver responses.
    pub fn new(
        rng: &mut (impl CryptoRng + RngCore),
        windows: impl IntoIterator<IntoIter = WI>,
        batch_len: RangeInclusive<usize>,
        security_strength: u8,
        active_security_key: Arc<ActiveSecurityKey>,
    ) -> Self
    where
        // Require Clone up-front to ensure Self will be iterable.
        WI: Iterator + Clone,
    {
        let windows = windows.into_iter();
        // Why not just require `WI: ExactSizeIterator`? Because iter chaining isn't guaranteed
        // to produce lengths that fit in `usize`, so we're forced to check at runtime.
        let (num_windows, max_windows) = windows.size_hint();
        assert_eq!(
            max_windows,
            Some(num_windows),
            "windows must have known len"
        );

        let (min_batch_len, max_batch_len) = batch_len.into_inner();
        assert!(1 < min_batch_len);
        assert!(min_batch_len <= max_batch_len);
        // We decrement the batch len range so the batches end up being the correct len when
        // the balancer is appended.
        let batch_len = (min_batch_len - 1)..=(max_batch_len - 1);
        let layouts = BatchLayouts::new(num_windows, batch_len);

        // Note that StdRng is a CSPRNG. We create `rng` so that batch crypto can run in
        // isolation from other program state so it's easier to parallelize, yet is still
        // dependent on R (and is reproducible if R is). Also, we can't merely clone R or
        // filler hashes will be duplicated.
        let rng = StdRng::from_seed(rng.gen());

        Self {
            rng,
            windows,
            layouts,
            security_strength,
            active_security_key,
        }
    }

    /// The total number of remaining queries across all batches, if they can fit in a `u64`.
    pub fn remaining_queries(&self) -> Option<u64> {
        self.layouts
            .remaining_queries()
            // add one balancer query per batch to the total queries
            .and_then(|queries| queries.checked_add(self.layouts.len()))
            .and_then(|queries| queries.try_into().ok())
    }
}

impl<WI> Iterator for QueryBatches<WI>
where
    WI: Clone + Iterator,
{
    type Item = BatchBuilder<WI>;

    fn next(&mut self) -> Option<Self::Item> {
        let layout = self.layouts.next()?;
        let rng = StdRng::from_seed(self.rng.gen());
        // Hopefully cloning the window iter won't be TOO expensive
        // (ideally the source sequence(s) should be Arced)
        // Also, this allows us to delay hashing to take place in the crypto future,
        // so all expensive stuff can be offloaded to worker threads.
        let batch_windows = self.windows.clone();
        let was_long_enough = advance_by(&mut self.windows, layout.real_queries);
        assert!(was_long_enough);
        Some(BatchBuilder {
            rng,
            batch_windows,
            layout,
            security_strength: self.security_strength,
            active_security_key: self.active_security_key.clone(),
        })
    }
}

/// Advance `iter` by `elements_to_skip` elements and return `true`, if possible.
/// If `iter` is too short, consume it fully and return `false`.
fn advance_by(iter: &mut impl Iterator, elements_to_skip: usize) -> bool {
    match elements_to_skip.checked_sub(1) {
        Some(n) => iter.nth(n).is_some(), // nth is potentially efficient, depending on the iter
        None => true,
    }
}

/// Holds the state necessary to build a batch of queries.
///
/// This is essentially a [`Future`]/closure... why not use one of those
/// instead?
/// * [`Future`]s shouldn't block or use a lot of CPU and this is computationally expensive.
///   We don't want to encourage calling it from within a future.
/// * Having a nice concrete type helps prevent crazy `where` causes, so we avoid closures.
///
/// [`Future`]: std::future::Future
pub struct BatchBuilder<WI> {
    rng: StdRng,
    batch_windows: WI,
    layout: BatchLayout,
    security_strength: u8,
    active_security_key: Arc<ActiveSecurityKey>,
}

impl<WI> BatchBuilder<WI> {
    /// Build a batch of [`CompressedQuery`]s.
    ///
    /// In addition to the queries, this also returns a [`BatchContext`] that can verify and
    /// merge keyserver responses.
    ///
    /// <div class="warning">
    /// This is computationally expensive, so avoid calling it from within async functions.
    /// </div>
    pub fn build<W, M>(mut self) -> (Arc<[CompressedQuery]>, BatchContext<M>)
    where
        WI: Iterator<Item = (W, M)>,
        W: AsRef<[u8]>,
    {
        let mut window_metadata = Vec::with_capacity(self.layout.real_queries);
        // Prevent unnecessarily checking size_hint here, for performance.
        let without_size_hint = std::iter::from_fn(|| self.batch_windows.next());
        let windows =
            without_size_hint
                .take(self.layout.real_queries)
                .map(|(window, metadatum)| {
                    window_metadata.push(metadatum);
                    window
                });
        let (windows, security_context) = setup_queries(
            self.rng,
            windows,
            self.layout.dummy_queries,
            self.security_strength,
        );
        let batch_metadata = BatchContext {
            security_context,
            active_security_key: self.active_security_key,
            window_metadata,
        };
        (windows, batch_metadata)
    }
}

/// Holds information necessary to verify and merge keyserver responses.
pub struct BatchContext<M> {
    security_context: QueriesSecurityContext,
    active_security_key: Arc<ActiveSecurityKey>,
    window_metadata: Vec<M>,
}

impl<M> BatchContext<M> {
    /// Verify and merge keyserver responses.
    ///
    /// In addition to the [`CompressedCompletedHashValue`]s, this also returns the
    /// window metadata (of this batch's windows) from the original window iterator.
    ///
    /// <div class="warning">
    /// This is computationally expensive, so avoid calling it from within async functions.
    /// </div>
    pub fn recombine(
        self,
        responses: &[(KeyserverId, Vec<CompressedHashPart>)],
    ) -> Result<(Vec<CompressedCompletedHashValue>, Vec<M>), QueryError> {
        self.security_context
            .recombine(responses, &self.active_security_key)
            .map(|hashes| (hashes, self.window_metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    use curve25519_dalek::RistrettoPoint;
    use rand::rngs::OsRng;
    use sha3::Sha3_512;

    use crate::prf::{KeyShare, Query};
    use crate::testutil::KeyShares;

    fn hash_via_key(
        key: &KeyShare,
        windows: impl IntoIterator<Item: AsRef<[u8]>>,
    ) -> Vec<CompressedCompletedHashValue> {
        windows
            .into_iter()
            .map(|window| {
                let rp = RistrettoPoint::hash_from_bytes::<Sha3_512>(window.as_ref());
                key.apply(Query::from_rp(rp)).compress().as_bytes().into()
            })
            .collect()
    }

    #[test]
    fn smoke_test() {
        let mut rng = OsRng;
        let windows = [("foo", 2), ("bar", 3), ("baz", 5)];
        // This should result in 2 batches with 2 windows, 1 padding and 1 balancer each.
        let batch_len = 3..=5;
        let security_strength = 18;
        let required_keyshares = 3..6;
        let additional_keyshares = 0..3;
        let keyshares = KeyShares::random(&mut rng, required_keyshares, additional_keyshares);

        let query_batches = QueryBatches::new(
            &mut rng,
            windows,
            batch_len.clone(),
            security_strength,
            Arc::new(keyshares.active_security_key.clone()),
        );

        let quorum_set = keyshares.random_quorum_set(&mut rng);
        let (hashes, metadata): (Vec<_>, Vec<_>) = query_batches
            .flat_map(|batch_builder| {
                let (queries, context) = batch_builder.build();
                let responses = keyshares.apply_keyshares(&quorum_set, queries.iter().copied());
                let (hashes, metadata) = context.recombine(&responses).unwrap();
                assert_eq!(hashes.len(), metadata.len());
                assert!(batch_len.contains(&hashes.len()));
                hashes.into_iter().zip(metadata)
            })
            .collect();

        assert_eq!(
            hashes,
            hash_via_key(&keyshares.secret, ["foo", "bar", "baz"])
        );
        assert_eq!(metadata, [2, 3, 5]);
    }

    #[test]
    fn batch_rng_is_not_replayed() {
        // THIS IS IMPORTANT FOR SECURITY!
        // Make sure the iterator is constructing per-batch RNG via
        //   let rng = StdRng::from_seed(self.rng.gen());
        // and not
        //   let rng = self.rng.clone();
        // because we don't want to replay any random information.
        let mut rng = OsRng;
        let windows = [("foo", ()), ("bar", ()), ("foo", ()), ("bar", ())];
        // This should result in 2 batches with 2 windows, 1 padding and 1 balancer each.
        let batch_len = 4..=4;
        let security_strength = 18;
        let required_keyshares = 1..2; // really 1..=1
        let additional_keyshares = 0..1; // really 0..=0
        let keyshares = KeyShares::random(&mut rng, required_keyshares, additional_keyshares);

        let query_batches = QueryBatches::new(
            &mut rng,
            windows,
            batch_len,
            security_strength,
            Arc::new(keyshares.active_security_key.clone()),
        );
        let query_batches = Vec::from_iter(query_batches.map(BatchBuilder::build));
        // The important check: We're not repeating batches.
        assert_ne!(
            query_batches[0].0, query_batches[1].0,
            "SECURITY PROBLEM: Batches replay the same RNG."
        );

        // Sanity-check that the previous assertion didn't accidentally pass
        // due to the batches having different windows.
        let quorum_set = keyshares.random_quorum_set(&mut rng);
        let hash_batches: Vec<_> = query_batches
            .into_iter()
            .map(|(queries, context)| {
                let responses = keyshares.apply_keyshares(&quorum_set, queries.iter().copied());
                context.recombine(&responses).unwrap().0
            })
            .collect();
        assert_eq!(
            hash_batches[0], hash_batches[1],
            "Test is broken due to batches operating on different data"
        );
    }

    // Important for performance: While QueryBatches::new should call size_hint,
    // BatchBuilder::build shouldn't.
    #[test]
    fn batch_builder_doesnt_call_size_hint() {
        #[derive(Clone)]
        struct SabotagedSizeHint<'a, I> {
            inner: I,
            sabotage: &'a Cell<bool>,
        }

        impl<I: Iterator> Iterator for SabotagedSizeHint<'_, I> {
            type Item = I::Item;

            fn next(&mut self) -> Option<Self::Item> {
                self.inner.next()
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                if self.sabotage.get() {
                    panic!("size_hint requested when not allowed");
                }
                self.inner.size_hint()
            }
        }

        let mut rng = OsRng;
        let sabotage = Cell::new(false);
        let windows = SabotagedSizeHint {
            inner: vec![("foo", ()), ("bar", ()), ("baz", ())].into_iter(),
            sabotage: &sabotage,
        };
        let batch_len = 3..=3;
        let security_strength = 18;
        let required_keyshares = 3..6;
        let additional_keyshares = 0..3;
        let keyshares = KeyShares::random(&mut rng, required_keyshares, additional_keyshares);
        let mut query_batches = QueryBatches::new(
            &mut rng,
            windows,
            batch_len,
            security_strength,
            Arc::new(keyshares.active_security_key),
        );

        sabotage.set(true);

        let batch_builder = query_batches.next().unwrap();
        batch_builder.build();
    }
}
