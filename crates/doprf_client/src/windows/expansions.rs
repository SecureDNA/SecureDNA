// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::Arc;

use quickdna::expansions::{Expansion, Expansions};
use quickdna::{Nucleotide, NucleotideAmbiguous};

/// Iterator of expansions of windows of ambiguous DNA
///
/// Yields pairs of (start..stop, nucleotides)
#[derive(Clone)]
pub struct WindowExpansions {
    windows: UnexpandedWindows,
    expansions: Option<Expansions>,
    max_window_expansions: Option<usize>,
}

/// Tracks the current window and amount of ambiguity
///
/// Unlike [T]::windows, this doesn't require holding on to a borrow, at the cost of extra
/// bounds checks. Also it keeps track of how much ambiguity a given window has.
/// These fields are grouped together because they tend to be borrowed together.
#[derive(Clone)]
struct UnexpandedWindows {
    src: Arc<[NucleotideAmbiguous]>,
    window_start: usize,
    window_len: usize,
    num_window_expansions: NumExpansions,
}

/// Tracks the number of expansions in a window
///
/// This should be cheaper than having the Expansions iterator recalculate it from scratch
/// every time.
///
/// Unlike a usize, this can store the number of expansions of any slice without overflowing or
/// allocating. It starts at one expansion and can only be multipled/divided by 1, 2, 3 or 4.
/// It should only be divided by its factors.
#[derive(Clone, Copy, Default)]
struct NumExpansions {
    twos: usize,
    threes: usize,
}

impl WindowExpansions {
    /// Creates a new iterator of all canonicalized expansions of DNA windows.
    ///
    /// Given a sequence of `src` DNA, the iterator yields `(index, expansion)` pairs, where each
    /// `expansion` is a canonicalized expansion (unambiguous DNA matching original ambiguous DNA)
    /// of the window at `&src[index..index+window_len]`. If `max_window_expansions` is supplied
    /// and a given window is sufficiently ambiguous to produce more expansions than
    /// `max_window_expansions`, expansions from that window are skipped.
    ///
    /// Expansions are yielded in ascending order of `index`, but beyond that no particular order
    /// is promised.
    pub fn new(
        src: Arc<[NucleotideAmbiguous]>,
        window_len: NonZeroUsize,
        max_window_expansions: Option<NonZeroUsize>,
    ) -> Self {
        assert!(window_len.get() < usize::MAX / 2); // prevents num_window_expansions from overflowing
        let window_len = window_len.get();
        let max_window_expansions = max_window_expansions.map(NonZeroUsize::get);
        Self {
            windows: UnexpandedWindows::new(src, window_len),
            expansions: None,
            max_window_expansions,
        }
    }
}

impl Iterator for WindowExpansions {
    type Item = (Range<usize>, Expansion);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(window) = self.windows.current() {
            if self.windows.is_unambiguous() {
                let nucs = window.iter().map(|&nuc| Nucleotide::try_from(nuc).unwrap());
                let idx = self.windows.window_start;
                let range = idx..idx + self.windows.window_len;
                let window = Expansion::from(Arc::from_iter(nucs));
                self.windows.shift();

                return Some((range, window));
            }

            if self.expansions.is_none()
                && self
                    .windows
                    .expansions_within_limit(self.max_window_expansions)
            {
                self.expansions = Some(Expansions::new(window));
            }
            if let Some(expansions) = &mut self.expansions {
                if let Some(expansion) = expansions.next() {
                    let idx = self.windows.window_start;
                    let range = idx..idx + self.windows.window_len;

                    return Some((range, expansion));
                }

                self.expansions = None;
            }

            self.windows.shift();
        }

        None
    }

    /// [`WindowExpansions`] produces an exact [`size_hint`](Self::size_hint) whenever that can
    /// fit in a [`usize`]. Otherwise, it returns `(usize::MAX, None)`.
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (|| {
            let mut total: usize = 0;
            let mut num_expansions_per_window = self.windows.num_expansions_per_window();
            if let Some(expansions) = &self.expansions {
                total = total.checked_add(expansions.size_hint().1?)?;
                num_expansions_per_window.next();
            }

            num_expansions_per_window.try_fold(total, |total, num_expansions| {
                if num_expansions.is_within_limit(self.max_window_expansions) {
                    total.checked_add(num_expansions.get()?)
                } else {
                    Some(total)
                }
            })
        })();
        (len.unwrap_or(usize::MAX), len)
    }
}

impl UnexpandedWindows {
    fn new(src: Arc<[NucleotideAmbiguous]>, window_len: usize) -> Self {
        let mut num_window_expansions = NumExpansions::new();
        if let Some(nucs) = src.get(..window_len) {
            for &nuc in nucs {
                num_window_expansions *= (nuc as u8).count_ones();
            }
        }

        Self {
            src,
            window_start: 0,
            window_len,
            num_window_expansions,
        }
    }

    fn shift(&mut self) {
        self.num_window_expansions /= (self.src[self.window_start] as u8).count_ones();
        if let Some(&nuc) = self.src.get(self.window_start + self.window_len) {
            self.num_window_expansions *= (nuc as u8).count_ones();
        }
        self.window_start += 1;
    }

    fn current(&self) -> Option<&[NucleotideAmbiguous]> {
        self.src
            .get(self.window_start..self.window_start + self.window_len)
    }

    fn is_unambiguous(&self) -> bool {
        self.num_window_expansions.is_one()
    }

    fn expansions_within_limit(&self, limit: Option<usize>) -> bool {
        self.num_window_expansions.is_within_limit(limit)
    }

    // Returns the NumExpansions for each window, starting with the current one
    fn num_expansions_per_window(&self) -> impl Iterator<Item = NumExpansions> + '_ {
        let additions = self.src.get(self.window_start + self.window_len..);
        let init = additions.map(|_| self.num_window_expansions);
        let mut additions = additions.unwrap_or_default().iter();
        let mut removals = self.src[self.window_start..].iter();
        std::iter::successors(init, move |num_expansions| {
            let mut num_expansions = *num_expansions;
            num_expansions *= (*additions.next()? as u8).count_ones();
            num_expansions /= (*removals.next()? as u8).count_ones();
            Some(num_expansions)
        })
    }
}

impl NumExpansions {
    fn new() -> Self {
        Self::default()
    }

    // Converts NumExpansions into a usize (`2^twos * 3^threes`), if possible.
    fn get(&self) -> Option<usize> {
        let threes_factor = 3usize.checked_pow(self.threes.try_into().ok()?)?;
        threes_factor.checked_shl(self.twos.try_into().ok()?)
    }

    fn is_one(&self) -> bool {
        self.twos == 0 && self.threes == 0
    }

    fn is_within_limit(&self, limit: Option<usize>) -> bool {
        if let Some(limit) = limit {
            self.get().is_some_and(|nx| nx <= limit)
        } else {
            true
        }
    }
}

impl std::ops::MulAssign<u32> for NumExpansions {
    fn mul_assign(&mut self, factor: u32) {
        match factor {
            1 => {}
            2 => self.twos += 1,
            3 => self.threes += 1,
            4 => self.twos += 2,
            _ => panic!("NumExpansions can only be multiplied by 1, 2, 3 or 4"),
        }
    }
}

impl std::ops::DivAssign<u32> for NumExpansions {
    fn div_assign(&mut self, factor: u32) {
        match factor {
            1 => {}
            2 => self.twos -= 1,
            3 => self.threes -= 1,
            4 => self.twos -= 2,
            _ => panic!("NumExpansions can only be divided by 1, 2, 3 or 4"),
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use quickcheck::{quickcheck, Arbitrary, Gen};

    use quickdna::{BaseSequence, DnaSequence};

    use super::*;

    fn to_dna(repr: &str) -> Vec<Nucleotide> {
        let dna: DnaSequence<Nucleotide> = repr.parse().unwrap();
        dna.as_slice().to_owned()
    }

    fn to_dna_amb(repr: &str) -> Arc<[NucleotideAmbiguous]> {
        let dna: DnaSequence<NucleotideAmbiguous> = repr.parse().unwrap();
        Arc::from(dna.as_slice())
    }

    #[test]
    fn smoke_test_unambiguous_windows() {
        let dna = to_dna_amb("ATGTGCGCGCGGCCCCGTGT"); // len = 20

        let window_len = NonZeroUsize::new(10).unwrap();
        let max_window_expansions = None;
        let windows = WindowExpansions::new(dna, window_len, max_window_expansions);

        let expected: Vec<(Range<usize>, _)> = [
            (0..10, "ATGTGCGCGC"),
            (1..11, "TGTGCGCGCG"),
            (2..12, "GTGCGCGCGG"),
            (3..13, "TGCGCGCGGC"),
            (4..14, "GCGCGCGGCC"),
            (5..15, "CGCGCGGCCC"),
            (6..16, "GCGCGGCCCC"),
            (7..17, "CGCGGCCCCG"),
            (8..18, "GCGGCCCCGT"),
            (9..19, "CGGCCCCGTG"),
            (10..20, "GGCCCCGTGT"),
        ]
        .into_iter()
        .map(|(i, w)| (i, to_dna(w)))
        .collect();

        assert_eq!(windows.size_hint(), (11, Some(11)));
        // Because the DNA is unambiguous, we know the exact order windows should be returned in.
        let windows: Vec<_> = windows.map(|(i, w)| (i, w.to_vec())).collect();
        assert_eq!(windows, expected);
    }

    #[test]
    fn smoke_test_ambiguous_windows() {
        let dna = to_dna_amb("ATNARTCTTTTAACGHAGGT"); // len = 20

        let window_len = NonZeroUsize::new(15).unwrap();
        let max_window_expansions = None;
        let windows = WindowExpansions::new(dna, window_len, max_window_expansions);

        // I expect the 15-nucleotide windows to look like:
        // offset 0 = ATNARTCTTTTAACG
        // offset 1 = TNARTCTTTTAACGH
        // offset 2 = NARTCTTTTAACGHA
        // offset 3 = ARTCTTTTAACGHAG
        // offset 4 = RTCTTTTAACGHAGG
        // offset 5 = TCTTTTAACGHAGGT

        // Expanding out N = {A, T, C, G} and R = {A, G} and H = {A, T, C}:
        let expected: HashSet<(Range<usize>, _)> = [
            (0..15, "ATAAATCTTTTAACG"),
            (0..15, "ATAAATCTTTTAACG"),
            (0..15, "ATAAGTCTTTTAACG"),
            (0..15, "ATTAATCTTTTAACG"),
            (0..15, "ATTAGTCTTTTAACG"),
            (0..15, "ATCAATCTTTTAACG"),
            (0..15, "ATCAGTCTTTTAACG"),
            (0..15, "ATGAATCTTTTAACG"),
            (0..15, "ATGAGTCTTTTAACG"),
            (1..16, "TAAATCTTTTAACGA"),
            (1..16, "TAAATCTTTTAACGT"),
            (1..16, "TAAATCTTTTAACGC"),
            (1..16, "TAAGTCTTTTAACGA"),
            (1..16, "TAAGTCTTTTAACGT"),
            (1..16, "TAAGTCTTTTAACGC"),
            (1..16, "TTAATCTTTTAACGA"),
            (1..16, "TTAATCTTTTAACGT"),
            (1..16, "TTAATCTTTTAACGC"),
            (1..16, "TTAGTCTTTTAACGA"),
            (1..16, "TTAGTCTTTTAACGT"),
            (1..16, "TTAGTCTTTTAACGC"),
            (1..16, "TCAATCTTTTAACGA"),
            (1..16, "TCAATCTTTTAACGT"),
            (1..16, "TCAATCTTTTAACGC"),
            (1..16, "TCAGTCTTTTAACGA"),
            (1..16, "TCAGTCTTTTAACGT"),
            (1..16, "TCAGTCTTTTAACGC"),
            (1..16, "TGAATCTTTTAACGA"),
            (1..16, "TGAATCTTTTAACGT"),
            (1..16, "TGAATCTTTTAACGC"),
            (1..16, "TGAGTCTTTTAACGA"),
            (1..16, "TGAGTCTTTTAACGT"),
            (1..16, "TGAGTCTTTTAACGC"),
            (2..17, "AAATCTTTTAACGAA"),
            (2..17, "AAATCTTTTAACGTA"),
            (2..17, "AAATCTTTTAACGCA"),
            (2..17, "AAGTCTTTTAACGAA"),
            (2..17, "AAGTCTTTTAACGTA"),
            (2..17, "AAGTCTTTTAACGCA"),
            (2..17, "TAATCTTTTAACGAA"),
            (2..17, "TAATCTTTTAACGTA"),
            (2..17, "TAATCTTTTAACGCA"),
            (2..17, "TAGTCTTTTAACGAA"),
            (2..17, "TAGTCTTTTAACGTA"),
            (2..17, "TAGTCTTTTAACGCA"),
            (2..17, "CAATCTTTTAACGAA"),
            (2..17, "CAATCTTTTAACGTA"),
            (2..17, "CAATCTTTTAACGCA"),
            (2..17, "CAGTCTTTTAACGAA"),
            (2..17, "CAGTCTTTTAACGTA"),
            (2..17, "CAGTCTTTTAACGCA"),
            (2..17, "GAATCTTTTAACGAA"),
            (2..17, "GAATCTTTTAACGTA"),
            (2..17, "GAATCTTTTAACGCA"),
            (2..17, "GAGTCTTTTAACGAA"),
            (2..17, "GAGTCTTTTAACGTA"),
            (2..17, "GAGTCTTTTAACGCA"),
            (3..18, "AATCTTTTAACGAAG"),
            (3..18, "AATCTTTTAACGTAG"),
            (3..18, "AATCTTTTAACGCAG"),
            (3..18, "AGTCTTTTAACGAAG"),
            (3..18, "AGTCTTTTAACGTAG"),
            (3..18, "AGTCTTTTAACGCAG"),
            (4..19, "ATCTTTTAACGAAGG"),
            (4..19, "ATCTTTTAACGTAGG"),
            (4..19, "ATCTTTTAACGCAGG"),
            (4..19, "GTCTTTTAACGAAGG"),
            (4..19, "GTCTTTTAACGTAGG"),
            (4..19, "GTCTTTTAACGCAGG"),
            (5..20, "TCTTTTAACGAAGGT"),
            (5..20, "TCTTTTAACGTAGGT"),
            (5..20, "TCTTTTAACGCAGGT"),
        ]
        .into_iter()
        .map(|(i, w)| (i, to_dna(w)))
        .collect();

        let num_windows = 8 + 24 + 24 + 6 + 6 + 3;
        assert_eq!(windows.size_hint(), (num_windows, Some(num_windows)));
        let windows: HashSet<_> = windows.map(|(i, w)| (i, w.to_vec())).collect();

        // Note: assert_eq! produces overwhelming failure messages; this shows helpful diffs
        let missing = &expected - &windows;
        let unexpected = &windows - &expected;
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "missing (index, window)s: {missing:?}\nunexpected (index, window)s: {unexpected:?}"
        );
    }

    #[test]
    fn smoke_test_ambiguous_windows_with_expansion_limit() {
        let dna = to_dna_amb("ATNARTCTTTTAACGHAGGT"); // len = 20

        let window_len = NonZeroUsize::new(15).unwrap();
        let max_window_expansions = Some(NonZeroUsize::new(20).unwrap());
        let windows = WindowExpansions::new(dna, window_len, max_window_expansions);

        // I expect the 15-nucleotide windows to look like:
        // offset 0 = ATNARTCTTTTAACG
        // offset 1 = TNARTCTTTTAACGH
        // offset 2 = NARTCTTTTAACGHA
        // offset 3 = ARTCTTTTAACGHAG
        // offset 4 = RTCTTTTAACGHAGG
        // offset 5 = TCTTTTAACGHAGGT

        // Expanding out N = {A, C, T, G} and R = {A, G} and H = {A, C, T}
        let expected: HashSet<(Range<usize>, _)> = [
            (0..15, "ATAAATCTTTTAACG"),
            (0..15, "ATAAATCTTTTAACG"),
            (0..15, "ATAAGTCTTTTAACG"),
            (0..15, "ATTAATCTTTTAACG"),
            (0..15, "ATTAGTCTTTTAACG"),
            (0..15, "ATCAATCTTTTAACG"),
            (0..15, "ATCAGTCTTTTAACG"),
            (0..15, "ATGAATCTTTTAACG"),
            (0..15, "ATGAGTCTTTTAACG"),
            // offset 1 = skipped due to having 24 expansions
            // offset 2 = skipped due to having 24 expansions
            (3..18, "AATCTTTTAACGAAG"),
            (3..18, "AATCTTTTAACGTAG"),
            (3..18, "AATCTTTTAACGCAG"),
            (3..18, "AGTCTTTTAACGAAG"),
            (3..18, "AGTCTTTTAACGTAG"),
            (3..18, "AGTCTTTTAACGCAG"),
            (4..19, "ATCTTTTAACGAAGG"),
            (4..19, "ATCTTTTAACGTAGG"),
            (4..19, "ATCTTTTAACGCAGG"),
            (4..19, "GTCTTTTAACGAAGG"),
            (4..19, "GTCTTTTAACGTAGG"),
            (4..19, "GTCTTTTAACGCAGG"),
            (5..20, "TCTTTTAACGAAGGT"),
            (5..20, "TCTTTTAACGTAGGT"),
            (5..20, "TCTTTTAACGCAGGT"),
        ]
        .into_iter()
        .map(|(i, w)| (i, to_dna(w)))
        .collect();

        let num_windows = 8 + 6 + 6 + 3;
        assert_eq!(windows.size_hint(), (num_windows, Some(num_windows)));
        let windows: HashSet<_> = windows.map(|(i, w)| (i, w.to_vec())).collect();

        // Note: assert_eq! produces overwhelming failure messages; this shows helpful diffs
        let missing = &expected - &windows;
        let unexpected = &windows - &expected;
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "missing (index, window)s: {missing:?}\nunexpected (index, window)s: {unexpected:?}"
        );
    }

    #[test]
    fn expansions_are_skipped_only_if_above_limit() {
        let limits_and_expected_lens = [
            (1, 0),
            (2, 0),
            (3, 3),
            (4, 3),
            (5, 3),
            (6, 6 + 6 + 3),
            (7, 6 + 6 + 3),
            (8, 8 + 6 + 6 + 3),
            (23, 8 + 6 + 6 + 3),
            (24, 8 + 24 + 24 + 6 + 6 + 3),
            (usize::MAX, 8 + 24 + 24 + 6 + 6 + 3),
        ];

        for (limit, expected_len) in limits_and_expected_lens {
            let dna = to_dna_amb("ATNARTCTTTTAACGHAGGT");
            let window_len = NonZeroUsize::new(15).unwrap();
            let max_window_expansions = Some(NonZeroUsize::new(limit).unwrap());
            let windows = WindowExpansions::new(dna, window_len, max_window_expansions);
            assert_eq!(
                windows.size_hint(),
                (expected_len, Some(expected_len)),
                "wrong iter length for max_window_expansions = {limit}"
            );
        }
    }

    #[test]
    fn capable_of_skipping_extremely_ambiguous_windows() {
        // The windows iter keeps a running tally of how many expansions are in the current
        // window in order to know which windows to skip. We need to make sure it's capable
        // of recovering from encountering enough expansions to overflow e.g. a u128.

        // We generate a series of A's, then N's, then A's, such that iterator length is
        // barely small enough to fit in a usize, yet the innermost window has too many
        // expansions to fit in a u128 (but is skipped).

        // This many Ns is guaranteed to have more expansions than can fit in a u128.
        let ambiguous_len = 128 / 2 + 1;
        // If window_len == ambiguous_len, then this is the minimum length of a series
        // of unambiguous nucleotides that would guarantee the first/last windows would
        // have a small enough number of expansions to fit in a usize.
        // The first/last windows would have 2^(usize::BITS - 2) expansions each,
        // resulting in a total of 2^(usize::BITS - 1) total items.
        let unambiguous_len = ambiguous_len - usize::BITS as usize / 2 + 1;

        // dna = [unambiguous_len A's, ambiguous_len N's, unambiguous_len A's]
        let mut dna = vec![NucleotideAmbiguous::A; 2 * unambiguous_len + ambiguous_len];
        dna[unambiguous_len..unambiguous_len + ambiguous_len].fill(NucleotideAmbiguous::N);

        let window_len = NonZeroUsize::new(ambiguous_len).unwrap();
        let max_window_expansions = Some(NonZeroUsize::MAX);
        let windows = WindowExpansions::new(dna.into(), window_len, max_window_expansions);

        let expected_len = 2usize.pow(usize::BITS - 1);
        assert_eq!(windows.size_hint(), (expected_len, Some(expected_len)));
    }

    #[test]
    fn regression_test_empty_dna() {
        let dna = to_dna_amb("");
        let window_len = NonZeroUsize::new(1).unwrap();
        let max_window_expansions = None;
        let mut windows = WindowExpansions::new(dna, window_len, max_window_expansions);
        assert_eq!(windows.size_hint(), (0, Some(0)));
        assert!(windows.next().is_none());
    }

    #[test]
    fn regression_test_single_nucleotide_with_excess_window_len() {
        let dna = to_dna_amb("A");
        let window_len = NonZeroUsize::new(2).unwrap();
        let max_window_expansions = None;
        let mut windows = WindowExpansions::new(dna, window_len, max_window_expansions);
        assert_eq!(windows.size_hint(), (0, Some(0)));
        assert!(windows.next().is_none());
    }

    #[test]
    fn regression_test_single_nucleotide_with_single_window_len() {
        let dna = to_dna_amb("A");
        let window_len = NonZeroUsize::new(1).unwrap();
        let max_window_expansions = None;
        let mut windows = WindowExpansions::new(dna, window_len, max_window_expansions);
        assert_eq!(windows.size_hint(), (1, Some(1)));
        assert_eq!(
            windows.next().map(|(i, w)| (i, w.to_vec())),
            Some((0..1, vec![Nucleotide::A]))
        );
        assert_eq!(windows.size_hint(), (0, Some(0)));
        assert!(windows.next().is_none());
    }

    // Max length of windows iterators that will be checked by the quickcheck tests
    const MAX_ITER_LEN: usize = 10000;

    #[derive(Clone, Debug)]
    struct WindowLen(usize);

    impl WindowLen {
        fn for_slice<T>(&self, slice: &[T]) -> NonZeroUsize {
            // Using len + 1 has two advantages: no div-by-zero and occasionally checking window sizes larger than the data size
            NonZeroUsize::new(1 + self.0 % (slice.len() + 1)).unwrap()
        }
    }

    impl Arbitrary for WindowLen {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(Arbitrary::arbitrary(g))
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(self.0.shrink().map(Self))
        }
    }

    #[derive(Clone, Debug)]
    struct SemiAmbiguousDna(Vec<NucleotideAmbiguous>);

    impl Arbitrary for SemiAmbiguousDna {
        fn arbitrary(g: &mut Gen) -> Self {
            let (dna, mut ambiguities): (Vec<Nucleotide>, Vec<(usize, NucleotideAmbiguous)>) =
                Arbitrary::arbitrary(g);
            ambiguities.truncate(dna.len() / 4);

            let mut dna: Vec<_> = dna.into_iter().map(NucleotideAmbiguous::from).collect();
            for (i, nuc) in ambiguities {
                dna.insert(i % (dna.len() + 1), nuc);
            }
            Self(dna)
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(self.0.shrink().map(Self))
        }
    }

    // One provider does a lot of oligos that match [ATCG]*(KNN|SNN|NNN|NNS|NNK)*[ATCG]*
    // Let's make sure we can handle that kind of thing tolerably well.
    #[derive(Clone, Debug)]
    struct Oligo(Vec<NucleotideAmbiguous>);

    impl Arbitrary for Oligo {
        fn arbitrary(g: &mut Gen) -> Self {
            use NucleotideAmbiguous::{K, N, S};
            let ambiguous_aa_type = g
                .choose(&[[K, N, N], [S, N, N], [N, N, N], [N, N, S], [N, N, K]])
                .unwrap();
            let (prefix, ambiguous_aas, suffix): (Vec<Nucleotide>, Vec<()>, Vec<Nucleotide>) =
                Arbitrary::arbitrary(g);

            let mut dna = Vec::new();
            dna.extend(prefix.into_iter().map(NucleotideAmbiguous::from));
            dna.extend(ambiguous_aas.iter().flat_map(|_| ambiguous_aa_type));
            dna.extend(suffix.into_iter().map(NucleotideAmbiguous::from));
            Self(dna)
        }
    }

    // Simple reference implementation for situations where there are no ambiguities
    fn unambiguous_windows_reference_implementation(
        dna: &[Nucleotide],
        window_len: NonZeroUsize,
    ) -> HashSet<(Range<usize>, Vec<Nucleotide>)> {
        let window_len = window_len.get();
        dna.windows(window_len)
            .enumerate()
            .map(|(i, window)| (i..i + window_len, window.to_vec()))
            .collect()
    }

    // Slightly more complicated reference implementation for handling ambiguities
    fn windows_reference_implementation(
        dna: &[NucleotideAmbiguous],
        window_len: NonZeroUsize,
        max_window_expansions: Option<NonZeroUsize>,
    ) -> HashSet<(Range<usize>, Vec<Nucleotide>)> {
        let window_len = window_len.get();
        let mut items = HashSet::new();
        for (i, window) in dna.windows(window_len).enumerate() {
            let expansions = Expansions::new(window);
            if let Some(limit) = max_window_expansions {
                if expansions.size_hint().0 > limit.get() {
                    continue;
                }
            }
            for expansion in expansions {
                items.insert((i..i + window_len, expansion.to_vec()));
            }
        }
        items
    }

    fn windows_match_reference_implementation(
        dna: Vec<NucleotideAmbiguous>,
        window_len: WindowLen,
        max_window_expansions: Option<NonZeroUsize>,
    ) -> bool {
        let window_len = window_len.for_slice(&dna);

        let actual = WindowExpansions::new(dna.clone().into(), window_len, max_window_expansions);

        // If there are too many windows to evaluate, we can't safely guage if things match.
        if actual.size_hint().0 > MAX_ITER_LEN {
            return true;
        }

        let actual: HashSet<_> = actual.map(|(i, w)| (i, w.to_vec())).collect();

        let reference = windows_reference_implementation(&dna, window_len, max_window_expansions);

        actual == reference
    }

    quickcheck! {
        fn unambiguous_windows_match_reference_implementation(
            dna: Vec<Nucleotide>,
            window_len: WindowLen,
            max_window_expansions: Option<NonZeroUsize>
        ) -> bool {
            let window_len = window_len.for_slice(&dna);

            let reference1 = unambiguous_windows_reference_implementation(&dna, window_len);

            let dna: Arc<_> = dna.into_iter().map(NucleotideAmbiguous::from).collect();
            let reference2 = windows_reference_implementation(&dna, window_len, max_window_expansions);

            let actual = WindowExpansions::new(dna, window_len, max_window_expansions);
            let actual: HashSet<_> = actual.map(|(i, w)| (i, w.to_vec())).collect();

            actual == reference1 && actual == reference2
        }

        fn very_ambiguous_windows_match_reference_implementation(
            dna: Vec<NucleotideAmbiguous>,
            window_len: WindowLen,
            max_window_expansions: Option<NonZeroUsize>
        ) -> bool {
            windows_match_reference_implementation(dna, window_len, max_window_expansions)
        }

        fn less_ambiguous_windows_match_reference_implementation(
            dna: SemiAmbiguousDna,
            window_len: WindowLen,
            max_window_expansions: Option<NonZeroUsize>
        ) -> bool {
            windows_match_reference_implementation(dna.0, window_len, max_window_expansions)
        }

        fn oligo_windows_match_reference_implementation(
            dna: Oligo,
            window_len: WindowLen,
            max_window_expansions: Option<NonZeroUsize>
        ) -> bool {
            windows_match_reference_implementation(dna.0, window_len, max_window_expansions)
        }

        // It's easy to calculate exactly how many windows unambiguous DNA should produce,
        // so this checks that the initial values of size_hints() match that.
        fn initial_dna_windows_size_hint_is_correct_for_unambiguous_dna(
            dna: Vec<Nucleotide>,
            window_len: WindowLen,
            max_window_expansions: Option<NonZeroUsize>
        ) -> bool {
            let window_len = window_len.for_slice(&dna);
            let expected_len = if 1 <= window_len.get() && window_len.get() <= dna.len() {
                dna.len() - window_len.get() + 1
            } else {
                0
            };
            let dna: Vec<_> = dna.into_iter().map(NucleotideAmbiguous::from).collect();
            let size_hint = WindowExpansions::new(dna.into(), window_len, max_window_expansions).size_hint();
            size_hint == (expected_len, Some(expected_len))
        }

        // This checks that the size_hints behave like size hints:
        // they decrement per item, and are 0 when there are no more items.
        fn windows_size_hint_accurately_predicts_length(
            dna: SemiAmbiguousDna,
            window_len: WindowLen,
            max_window_expansions: Option<NonZeroUsize>
        ) -> bool {
            let window_len = window_len.for_slice(&dna.0);
            let mut windows = WindowExpansions::new(dna.0.into(), window_len, max_window_expansions);
            let (lower, upper) = windows.size_hint();
            if lower > MAX_ITER_LEN {
                return true; // too large to check
            }
            // This iterator should be capable of predicting exact sizes if its len <= usize::MAX.
            if upper != Some(lower) {
                return false;
            }
            let mut prev_len = lower;
            while windows.next().is_some() {
                let (lower, upper) = windows.size_hint();
                // Make sure:
                // * We don't have an element when we said we wouldn't.
                // * Our size_hint() has decreased by 1.
                // * The size_hint is exact.
                if prev_len == 0 || lower != prev_len - 1 || upper != Some(lower) {
                    return false;
                }
                prev_len = lower;
            }
            windows.size_hint() == (0, Some(0))
        }

        fn windows_are_returned_in_ascending_order_of_offset(
            dna: SemiAmbiguousDna,
            window_len: WindowLen,
            max_window_expansions: Option<NonZeroUsize>
        ) -> bool {
            let window_len = window_len.for_slice(&dna.0);
            let mut windows = WindowExpansions::new(dna.0.into(), window_len, max_window_expansions).map(|(i, _)| i.start);
            if windows.size_hint().0 > MAX_ITER_LEN {
                return true; // too large to check
            }
            if let Some(mut prev_index) = windows.next() {
                for i in windows {
                    if i < prev_index {
                        return false;
                    }
                    prev_index = i;
                }
            }
            true
        }
    }
}
