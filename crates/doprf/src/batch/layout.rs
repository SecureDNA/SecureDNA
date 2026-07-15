// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Determines how to split windows into evenly sized batches.

use std::ops::RangeInclusive;

/// Calculates multiple evenly sized [`BatchLayout`]s for a given number of windows.
///
/// Given a total number of queries and min/max batch sizes, this calculates a series of
/// [`BatchLayout`]s such that:
///
/// * The sum of [`BatchLayout::real_queries`] is the total number of queries you asked for.
/// * The [`BatchLayout::len`] of each batch falls within `min..=max` batch len.
/// * The maximum and minimum [`BatchLayout::real_queries`] differ by at most one.
/// * It uses the minimum possible number of batches and dummy queries necessary to fulfill the
///   above constraints.
/// * [`BatchLayout`]s are yielded in descending order of [`BatchLayout::real_queries`].
///
/// # Example
///
/// ```
/// use doprf::batch::layout::{BatchLayout, BatchLayouts};
///
/// let number_of_queries = 124;
/// let batch_len = 45..=50;
/// let layouts = Vec::from_iter(BatchLayouts::new(number_of_queries, batch_len));
/// // `BatchLayouts` figures out that to layout 124 queries into batches of
/// // length 45..=50, we will need 3 batches. Evenly distributing the real queries
/// // and padding with dummy queries to bring the lengths up to 45 results in:
/// assert_eq!(layouts, [
///     BatchLayout { real_queries: 42, dummy_queries: 3 },
///     BatchLayout { real_queries: 41, dummy_queries: 4 },
///     BatchLayout { real_queries: 41, dummy_queries: 4 },
/// ]);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct BatchLayouts {
    num_large_batches: usize,
    large_batch_layout: BatchLayout,
    num_small_batches: usize,
    small_batch_layout: BatchLayout,
}

impl BatchLayouts {
    /// Create a new [`BatchLayouts`].
    ///
    /// `num_queries` is the total number of queries the batches need support.
    ///
    /// `batch_len` controls the min/max size of the batches.
    /// Note that it is a programming error for the maximum to be 0.
    pub fn new(num_queries: usize, batch_len: RangeInclusive<usize>) -> Self {
        let (min_batch_len, max_batch_len) = batch_len.into_inner();

        assert!(0 < max_batch_len);
        assert!(min_batch_len <= max_batch_len);

        let num_batches = (0..num_queries).step_by(max_batch_len).len();
        if num_batches == 0 {
            return Self {
                num_large_batches: 0,
                large_batch_layout: Self::layout(0, min_batch_len),
                num_small_batches: 0,
                small_batch_layout: Self::layout(0, min_batch_len),
            };
        }
        let queries_per_small_batch = num_queries / num_batches;
        let num_large_batches = num_queries % num_batches;
        let num_small_batches = num_batches - num_large_batches;

        let small_batch_layout = Self::layout(queries_per_small_batch, min_batch_len);
        // It's ok for the .saturating_add(1) to saturate because in order for that to happen:
        //   queries_per_small_batch == usize::MAX
        //   so num_batches == 1
        //   so num_large_batches == 0
        //   so the layout doesn't matter.
        let large_batch_layout =
            Self::layout(queries_per_small_batch.saturating_add(1), min_batch_len);

        Self {
            num_large_batches,
            large_batch_layout,
            num_small_batches,
            small_batch_layout,
        }
    }

    fn layout(real_queries: usize, min_batch_len: usize) -> BatchLayout {
        BatchLayout {
            real_queries,
            dummy_queries: min_batch_len.saturating_sub(real_queries),
        }
    }

    /// Returns total queries (including dummy queries) across all remaining [`BatchLayout`]s.
    ///
    /// If that cannot fit in a `usize`, this returns `None`. This is suitable for calculating
    /// total request sizes.
    pub fn remaining_queries(&self) -> Option<usize> {
        // Note: This is just calculating:
        //   big_batches * big_batch_size + small_batches * small_batch_size
        // Also, the definition of Self::layout() prevents layout.len() from overflowing.
        let large_batch_queries = self
            .num_large_batches
            .checked_mul(self.large_batch_layout.len())?;
        let small_batch_queries = self
            .num_small_batches
            .checked_mul(self.small_batch_layout.len())?;
        large_batch_queries.checked_add(small_batch_queries)
    }
}

impl Iterator for BatchLayouts {
    type Item = BatchLayout;

    fn next(&mut self) -> Option<Self::Item> {
        if self.num_large_batches > 0 {
            self.num_large_batches -= 1;
            Some(self.large_batch_layout)
        } else if self.num_small_batches > 0 {
            self.num_small_batches -= 1;
            Some(self.small_batch_layout)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.num_large_batches + self.num_small_batches;
        (len, Some(len))
    }
}

impl ExactSizeIterator for BatchLayouts {}

/// Describes the layout of an individual batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchLayout {
    /// How many queries should be derived from actual windows.
    pub real_queries: usize,
    /// How many queries should be randomly generated as padding.
    pub dummy_queries: usize,
}

impl BatchLayout {
    /// Total size of a batch in queries.
    pub fn len(&self) -> usize {
        self.real_queries + self.dummy_queries
    }

    /// True iff the batch is empty. (probably shouldn't happen in practice)
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck::{TestResult, quickcheck};

    fn sane_batch_layouts(
        num_queries: usize,
        batch_len: RangeInclusive<usize>,
    ) -> Option<BatchLayouts> {
        if *batch_len.end() == 0 || batch_len.end() < batch_len.start() {
            return None;
        }
        let layouts = BatchLayouts::new(num_queries, batch_len);
        // Skip excessively large layouts so we don't waste resources iterating a lot
        if layouts.len() > 1000000 || layouts.remaining_queries().is_none() {
            return None;
        }
        Some(layouts)
    }

    quickcheck! {

        fn batch_layouts_preserve_total_queries(
            num_queries: usize,
            min_batch_len: usize,
            max_batch_len: usize
        ) -> TestResult {
            let layouts = sane_batch_layouts(num_queries, min_batch_len..=max_batch_len);
            let Some(layouts) = layouts else {
                return TestResult::discard();
            };
            let batched_queries: usize = layouts.map(|layout| layout.real_queries).sum();
            TestResult::from_bool(batched_queries == num_queries)
        }

        fn batch_layouts_never_violate_min_len(
            num_queries: usize,
            min_batch_len: usize,
            max_batch_len: usize
        ) -> TestResult {
            let layouts = sane_batch_layouts(num_queries, min_batch_len..=max_batch_len);
            let Some(mut layouts) = layouts else {
                return TestResult::discard();
            };
            let are_valid = layouts.all(|layout| layout.len() >= min_batch_len);
            TestResult::from_bool(are_valid)
        }

        fn batch_layouts_never_violate_max_len(
            num_queries: usize,
            min_batch_len: usize,
            max_batch_len: usize
        ) -> TestResult {
            let layouts = sane_batch_layouts(num_queries, min_batch_len..=max_batch_len);
            let Some(mut layouts) = layouts else {
                return TestResult::discard();
            };
            let are_valid = layouts.all(|layout| layout.len() <= max_batch_len);
            TestResult::from_bool(are_valid)
        }

        fn batch_layouts_use_minimum_number_of_batches(
            num_queries: usize,
            min_batch_len: usize,
            max_batch_len: usize
        ) -> TestResult {
            let layouts = sane_batch_layouts(num_queries, min_batch_len..=max_batch_len);
            let Some(layouts) = layouts else {
                return TestResult::discard();
            };
            let is_minimal = layouts.len() <= (0..num_queries).step_by(max_batch_len).len();
            TestResult::from_bool(is_minimal)
        }

        // I suppose this is a stricter version of batch_layouts_use_minimum_number_of_batches.
        // In any case, this demonstrates a nice property of the current code.
        fn batch_layouts_evenly_distribute_queries(
            num_queries: usize,
            min_batch_len: usize,
            max_batch_len: usize
        ) -> TestResult {
            let layouts = sane_batch_layouts(num_queries, min_batch_len..=max_batch_len);
            let Some(layouts) = layouts else {
                return TestResult::discard();
            };
            let queries_per_batch = layouts.map(|l| l.real_queries);
            if queries_per_batch.len() == 0 {
                return TestResult::discard();
            }
            let min_queries = queries_per_batch.clone().min().unwrap();
            let max_queries = queries_per_batch.clone().max().unwrap();
            TestResult::from_bool(max_queries >= min_queries && max_queries - min_queries <= 1)
        }

        fn batch_layouts_handle_sane_sizes(
            num_queries: usize,
            min_batch_len: usize,
            max_batch_len: usize
        ) -> TestResult {
            if max_batch_len == 0 || max_batch_len < min_batch_len {
                return TestResult::discard();
            }
            // Above this, I start worrying that it's reasonable for ChunkLayouts to
            // reject things on the basis of overflow.
            let sanity_cap = u64::MAX.try_into().unwrap_or(usize::MAX) / 4;
            if num_queries > sanity_cap || min_batch_len > sanity_cap || max_batch_len > sanity_cap
            {
                return TestResult::discard();
            }
            let layouts = BatchLayouts::new(num_queries, min_batch_len..=max_batch_len);
            TestResult::from_bool(layouts.remaining_queries().is_some())
        }

        fn batch_layouts_handle_pathologic_batch_size(
            num_queries: usize,
            min_batch_len: usize
        ) -> TestResult {
            let max_batch_len = u64::MAX.try_into().unwrap_or(usize::MAX);
            if num_queries > max_batch_len || min_batch_len > max_batch_len {
                return TestResult::discard();
            }
            let mut layouts = BatchLayouts::new(num_queries, min_batch_len..=max_batch_len);
            if layouts.remaining_queries().is_none() {
                return TestResult::failed();
            }
            if num_queries > 0 && layouts.next().is_none_or(|l| l.real_queries != num_queries) {
                return TestResult::failed();
            }
            if layouts.next().is_some() {
                return TestResult::failed();
            }
            TestResult::passed()
        }
    }
}
