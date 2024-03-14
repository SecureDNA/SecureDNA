// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::Arc;

use quickdna::{
    canonical::Canonical, BaseSequence, DnaSequenceStrict, Nucleotide, NucleotideAmbiguous,
};

use super::expansions::WindowExpansions;

/// Iterator of canonicalized expansions of windows of ambiguous DNA
#[derive(Clone)]
pub struct DnaWindows {
    windows: WindowExpansions,
    output: DnaWindow,
}

/// Canonicalized expansion of a given window
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnaWindow(Arc<[Nucleotide]>);

impl DnaWindows {
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
        src: Vec<NucleotideAmbiguous>,
        window_len: NonZeroUsize,
        max_window_expansions: Option<NonZeroUsize>,
    ) -> Self {
        let windows = WindowExpansions::new(src.into(), window_len, max_window_expansions);
        Self {
            windows,
            output: DnaWindow::new(window_len.get()),
        }
    }
}

impl Iterator for DnaWindows {
    type Item = (Range<usize>, DnaWindow);

    fn next(&mut self) -> Option<Self::Item> {
        let (indexes, nucs) = self.windows.next()?;
        let window = self.output.store(Canonical::new(nucs.iter().copied()));
        Some((indexes, window))
    }

    /// [`DnaWindows`] produces an exact [`size_hint`](Self::size_hint) whenever that can fit
    /// in a [`usize`]. Otherwise, it returns `(usize::MAX, None)`.
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.windows.size_hint()
    }
}

impl DnaWindow {
    fn new(window_len: usize) -> Self {
        let storage = Arc::from_iter((0..window_len).map(|_| Nucleotide::A));
        Self(storage)
    }

    // Attempts to stores iter in this DnaWindow
    // (or a new one if this cannot be mutated due to being shared)
    // Note: Iter must be the same length as this DnaWindow
    fn store(&mut self, iter: impl Iterator<Item = Nucleotide>) -> Self {
        // Can't use Arc::make_mut because [T] is unsized
        match Arc::get_mut(&mut self.0) {
            Some(buf) => {
                // TODO: maybe check that this consumes all of iter?
                for (dst, src) in buf.iter_mut().zip(iter) {
                    *dst = src;
                }
            }
            None => self.0 = iter.collect(),
        }
        self.clone()
    }

    /// Produces a [`DnaSequenceStrict`] from [`DnaWindow`].
    ///
    /// This takes *O*(*N*) time.
    pub fn to_dna(&self) -> DnaSequenceStrict {
        DnaSequenceStrict::new(self.to_vec())
    }
}

impl From<DnaWindow> for DnaSequenceStrict {
    fn from(expansion: DnaWindow) -> Self {
        expansion.to_dna()
    }
}

impl std::ops::Deref for DnaWindow {
    type Target = [Nucleotide];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[Nucleotide]> for DnaWindow {
    fn as_ref(&self) -> &[Nucleotide] {
        self
    }
}

impl std::cmp::PartialEq<[Nucleotide]> for DnaWindow {
    fn eq(&self, other: &[Nucleotide]) -> bool {
        self.as_ref() == other
    }
}

impl std::cmp::PartialEq<DnaSequenceStrict> for DnaWindow {
    fn eq(&self, other: &DnaSequenceStrict) -> bool {
        self.as_ref() == other.as_slice()
    }
}

impl std::fmt::Debug for DnaWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_tuple("DnaWindow")
            .field(&self.to_dna().to_string())
            .finish()
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use quickcheck::{quickcheck, Arbitrary, Gen};

    use quickdna::{expansions::Expansions, DnaSequence};

    use super::*;

    fn to_dna(repr: &str) -> Vec<Nucleotide> {
        let dna: DnaSequence<Nucleotide> = repr.parse().unwrap();
        dna.as_slice().to_owned()
    }

    fn to_dna_amb(repr: &str) -> Vec<NucleotideAmbiguous> {
        let dna: DnaSequence<NucleotideAmbiguous> = repr.parse().unwrap();
        dna.as_slice().to_owned()
    }

    #[test]
    fn smoke_test_unambiguous_dna_windows() {
        let dna = to_dna_amb("ATGTGCGCGCGGCCCCGTGT"); // len = 20

        let window_len = NonZeroUsize::new(10).unwrap();
        let max_window_expansions = None;
        let windows = DnaWindows::new(dna, window_len, max_window_expansions);

        // I expect the 10-nucleotide windows to look like:
        // offset  0 = ATGTGCGCGC
        // offset  1 = TGTGCGCGCG
        // offset  2 = GTGCGCGCGG
        // offset  3 = TGCGCGCGGC
        // offset  4 = GCGCGCGGCC
        // offset  5 = CGCGCGGCCC
        // offset  6 = GCGCGGCCCC
        // offset  7 = CGCGGCCCCG
        // offset  8 = GCGGCCCCGT
        // offset  9 = CGGCCCCGTG
        // offset 10 = GGCCCCGTGT

        // Canonicalizing those yields:
        let expected: Vec<(Range<usize>, _)> = [
            (0..10, "ATATATCTCG"),
            (1..11, "ATATATACAC"),
            (2..12, "AATATATACA"),
            (3..13, "ATTATATATC"),
            (4..14, "AATTATATAT"),
            (5..15, "AAATTATATA"),
            (6..16, "AAAATTATAT"),
            (7..17, "ATATTAAAAT"),
            (8..18, "ATAATTTTAC"),
            (9..19, "ATACCCCAAC"),
            (10..20, "AATTTTACAC"),
        ]
        .into_iter()
        .map(|(i, w)| (i, to_dna(w)))
        .collect();

        assert_eq!(windows.size_hint(), (11, Some(11)));
        // Because the DNA is ambiguous, we know the exact order windows should be returned in.
        let windows: Vec<_> = windows.map(|(i, w)| (i, w.to_vec())).collect();
        assert_eq!(windows, expected);
    }

    #[test]
    fn smoke_test_ambiguous_dna_windows() {
        let dna = to_dna_amb("ATNARTCTTTTAACGHAGGT"); // len = 20

        let window_len = NonZeroUsize::new(15).unwrap();
        let max_window_expansions = None;
        let windows = DnaWindows::new(dna, window_len, max_window_expansions);

        // I expect the 15-nucleotide windows to look like:
        // offset 0 = ATNARTCTTTTAACG
        // offset 1 = TNARTCTTTTAACGH
        // offset 2 = NARTCTTTTAACGHA
        // offset 3 = ARTCTTTTAACGHAG
        // offset 4 = RTCTTTTAACGHAGG
        // offset 5 = TCTTTTAACGHAGGT

        // Expanding out N = {A, T, C, G} and R = {A, G} and H = {A, T, C}:
        // offset 0 = ATAAATCTTTTAACG
        //            ATAAGTCTTTTAACG
        //            ATTAATCTTTTAACG
        //            ATTAGTCTTTTAACG
        //            ATCAATCTTTTAACG
        //            ATCAGTCTTTTAACG
        //            ATGAATCTTTTAACG
        //            ATGAGTCTTTTAACG
        // offset 1 = TAAATCTTTTAACGA
        //            TAAATCTTTTAACGT
        //            TAAATCTTTTAACGC
        //            TAAGTCTTTTAACGA
        //            TAAGTCTTTTAACGT
        //            TAAGTCTTTTAACGC
        //            TTAATCTTTTAACGA
        //            TTAATCTTTTAACGT
        //            TTAATCTTTTAACGC
        //            TTAGTCTTTTAACGA
        //            TTAGTCTTTTAACGT
        //            TTAGTCTTTTAACGC
        //            TCAATCTTTTAACGA
        //            TCAATCTTTTAACGT
        //            TCAATCTTTTAACGC
        //            TCAGTCTTTTAACGA
        //            TCAGTCTTTTAACGT
        //            TCAGTCTTTTAACGC
        //            TGAATCTTTTAACGA
        //            TGAATCTTTTAACGT
        //            TGAATCTTTTAACGC
        //            TGAGTCTTTTAACGA
        //            TGAGTCTTTTAACGT
        //            TGAGTCTTTTAACGC
        // offset 2 = AAATCTTTTAACGAA
        //            AAATCTTTTAACGTA
        //            AAATCTTTTAACGCA
        //            AAGTCTTTTAACGAA
        //            AAGTCTTTTAACGTA
        //            AAGTCTTTTAACGCA
        //            TAATCTTTTAACGAA
        //            TAATCTTTTAACGTA
        //            TAATCTTTTAACGCA
        //            TAGTCTTTTAACGAA
        //            TAGTCTTTTAACGTA
        //            TAGTCTTTTAACGCA
        //            CAATCTTTTAACGAA
        //            CAATCTTTTAACGTA
        //            CAATCTTTTAACGCA
        //            CAGTCTTTTAACGAA
        //            CAGTCTTTTAACGTA
        //            CAGTCTTTTAACGCA
        //            GAATCTTTTAACGAA
        //            GAATCTTTTAACGTA
        //            GAATCTTTTAACGCA
        //            GAGTCTTTTAACGAA
        //            GAGTCTTTTAACGTA
        //            GAGTCTTTTAACGCA
        // offset 3 = AATCTTTTAACGAAG
        //            AATCTTTTAACGTAG
        //            AATCTTTTAACGCAG
        //            AGTCTTTTAACGAAG
        //            AGTCTTTTAACGTAG
        //            AGTCTTTTAACGCAG
        // offset 4 = ATCTTTTAACGAAGG
        //            ATCTTTTAACGTAGG
        //            ATCTTTTAACGCAGG
        //            GTCTTTTAACGAAGG
        //            GTCTTTTAACGTAGG
        //            GTCTTTTAACGCAGG
        // offset 5 = TCTTTTAACGAAGGT
        //            TCTTTTAACGTAGGT
        //            TCTTTTAACGCAGGT

        // Canonicalizing those yields:
        let expected: HashSet<(Range<usize>, _)> = [
            (0..15, "ATAAATCTTTTAACG"),
            (0..15, "ATAACTGTTTTAAGC"),
            (0..15, "ATTAATCTTTTAACG"),
            (0..15, "ATTACTGTTTTAAGC"),
            (0..15, "ATCAATCTTTTAACG"),
            (0..15, "ATCAGTCTTTTAACG"),
            (0..15, "ATCAATGTTTTAAGC"),
            (0..15, "ATCACTGTTTTAAGC"),
            (1..16, "ATTTACAAAATTCGT"),
            (1..16, "ATTTACAAAATTCGA"),
            (1..16, "ATACCGGGGAGCCCG"),
            (1..16, "ATTCAGAAAATTGCT"),
            (1..16, "ATTCAGAAAATTGCA"),
            (1..16, "ATACCGGGGAGTCCG"),
            (1..16, "AATTACAAAATTCGT"),
            (1..16, "AATTACAAAATTCGA"),
            (1..16, "AATTACAAAATTCGC"),
            (1..16, "AATCAGAAAATTGCT"),
            (1..16, "AATCAGAAAATTGCA"),
            (1..16, "AATCAGAAAATTGCG"),
            (1..16, "ATCAAGGGGCGAACG"),
            (1..16, "ATCCATAAAACCTGA"),
            (1..16, "ATACCGGGGAGCCAG"),
            (1..16, "ATCAAGGGGCGTACG"),
            (1..16, "ATCGATAAAACCTGA"),
            (1..16, "ATACCGGGGAGTCAG"),
            (1..16, "ATCAAGGGGCGAATG"),
            (1..16, "ATCCAGAAAACCGTA"),
            (1..16, "ATACCGGGGAGCCTG"),
            (1..16, "ATCAAGGGGCGTATG"),
            (1..16, "ATCTAGAAAACCGTA"),
            (1..16, "ATACCGGGGAGTCTG"),
            (2..17, "AAATCTTTTAACGAA"),
            (2..17, "AAATCTTTTAACGTA"),
            (2..17, "AAATCTTTTAACGCA"),
            (2..17, "AATCAAGGGGCGTAA"),
            (2..17, "AATCGCCCCAAGTCA"),
            (2..17, "AATCGCCCCAAGTGA"),
            (2..17, "AATCAAGGGGCGAAG"),
            (2..17, "ATTACAAAATTCGAT"),
            (2..17, "ATTACAAAATTCGCT"),
            (2..17, "AATCAAGGGGCGTAG"),
            (2..17, "ATCAGAAAATTGCAT"),
            (2..17, "ATCAGAAAATTGCGT"),
            (2..17, "AATCAAGGGGCGAAC"),
            (2..17, "ATTCACCCCTTAGCT"),
            (2..17, "ATTCACCCCTTAGAT"),
            (2..17, "AATCAAGGGGCGTAC"),
            (2..17, "ATCGAATTTTGTCAG"),
            (2..17, "ATCTAAGGGGTGCAT"),
            (2..17, "AATCAAGGGGCGAAT"),
            (2..17, "ATTCGCCCCTTGACT"),
            (2..17, "ATTCGCCCCTTGAGT"),
            (2..17, "AATCAAGGGGCGTAT"),
            (2..17, "ATACGCCCCTTGACT"),
            (2..17, "ATACGCCCCTTGAGT"),
            (3..18, "AATCTTTTAACGAAG"),
            (3..18, "AATCTTTTAACGTAG"),
            (3..18, "AATCTTTTAACGCAG"),
            (3..18, "ATTACTTGGGGCGAT"),
            (3..18, "ATCAGTTCCCCGCAT"),
            (3..18, "ATCACTTGGGGCGAT"),
            (4..19, "AATTACTTGGGGCGT"),
            (4..19, "AATCAGTTCCCCGCT"),
            (4..19, "AATCACTTGGGGCGT"),
            (4..19, "AATTACTTGGGGCGA"),
            (4..19, "AATCAGTTCCCCGCA"),
            (4..19, "AATCACTTGGGGCGA"),
            (5..20, "ATAAAACCTGCCGGA"),
            (5..20, "ATAAAACCTGACGGA"),
            (5..20, "ATAAAACCTGTCGGA"),
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
    fn smoke_test_ambiguous_dna_windows_with_expansion_limit() {
        let dna = to_dna_amb("ATNARTCTTTTAACGHAGGT"); // len = 20

        let window_len = NonZeroUsize::new(15).unwrap();
        let max_window_expansions = Some(NonZeroUsize::new(20).unwrap());
        let windows = DnaWindows::new(dna, window_len, max_window_expansions);

        // I expect the 15-nucleotide windows to look like:
        // offset 0 = ATNARTCTTTTAACG
        // offset 1 = TNARTCTTTTAACGH
        // offset 2 = NARTCTTTTAACGHA
        // offset 3 = ARTCTTTTAACGHAG
        // offset 4 = RTCTTTTAACGHAGG
        // offset 5 = TCTTTTAACGHAGGT

        // Expanding out N = {A, C, T, G} and R = {A, G} and H = {A, C, T}
        // offset 0 = ATAAATCTTTTAACG
        //            ATAAGTCTTTTAACG
        //            ATTAATCTTTTAACG
        //            ATTAGTCTTTTAACG
        //            ATCAATCTTTTAACG
        //            ATCAGTCTTTTAACG
        //            ATGAATCTTTTAACG
        //            ATGAGTCTTTTAACG
        // offset 1 = skipped due to having 24 expansions
        // offset 2 = skipped due to having 24 expansions
        // offset 3 = AATCTTTTAACGAAG
        //            AATCTTTTAACGTAG
        //            AATCTTTTAACGCAG
        //            AGTCTTTTAACGAAG
        //            AGTCTTTTAACGTAG
        //            AGTCTTTTAACGCAG
        // offset 4 = ATCTTTTAACGAAGG
        //            ATCTTTTAACGTAGG
        //            ATCTTTTAACGCAGG
        //            GTCTTTTAACGAAGG
        //            GTCTTTTAACGTAGG
        //            GTCTTTTAACGCAGG
        // offset 5 = TCTTTTAACGAAGGT
        //            TCTTTTAACGTAGGT
        //            TCTTTTAACGCAGGT

        // Canonicalizing those yields:
        let expected: HashSet<(Range<usize>, _)> = [
            (0..15, "ATAAATCTTTTAACG"),
            (0..15, "ATAACTGTTTTAAGC"),
            (0..15, "ATTAATCTTTTAACG"),
            (0..15, "ATTACTGTTTTAAGC"),
            (0..15, "ATCAATCTTTTAACG"),
            (0..15, "ATCAGTCTTTTAACG"),
            (0..15, "ATCAATGTTTTAAGC"),
            (0..15, "ATCACTGTTTTAAGC"),
            (3..18, "AATCTTTTAACGAAG"),
            (3..18, "AATCTTTTAACGTAG"),
            (3..18, "AATCTTTTAACGCAG"),
            (3..18, "ATTACTTGGGGCGAT"),
            (3..18, "ATCAGTTCCCCGCAT"),
            (3..18, "ATCACTTGGGGCGAT"),
            (4..19, "AATTACTTGGGGCGT"),
            (4..19, "AATCAGTTCCCCGCT"),
            (4..19, "AATCACTTGGGGCGT"),
            (4..19, "AATTACTTGGGGCGA"),
            (4..19, "AATCAGTTCCCCGCA"),
            (4..19, "AATCACTTGGGGCGA"),
            (5..20, "ATAAAACCTGCCGGA"),
            (5..20, "ATAAAACCTGACGGA"),
            (5..20, "ATAAAACCTGTCGGA"),
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
            let windows = DnaWindows::new(dna, window_len, max_window_expansions);
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
        let windows = DnaWindows::new(dna, window_len, max_window_expansions);

        let expected_len = 2usize.pow(usize::BITS - 1);
        assert_eq!(windows.size_hint(), (expected_len, Some(expected_len)));
    }

    #[test]
    fn regression_test_empty_dna() {
        let dna = vec![];
        let window_len = NonZeroUsize::new(1).unwrap();
        let max_window_expansions = None;
        let mut windows = DnaWindows::new(dna, window_len, max_window_expansions);
        assert_eq!(windows.size_hint(), (0, Some(0)));
        assert!(windows.next().is_none());
    }

    #[test]
    fn regression_test_single_nucleotide_with_excess_window_len() {
        let dna = [NucleotideAmbiguous::A].to_vec();
        let window_len = NonZeroUsize::new(2).unwrap();
        let max_window_expansions = None;
        let mut windows = DnaWindows::new(dna, window_len, max_window_expansions);
        assert_eq!(windows.size_hint(), (0, Some(0)));
        assert!(windows.next().is_none());
    }

    #[test]
    fn regression_test_single_nucleotide_with_single_window_len() {
        let dna = [NucleotideAmbiguous::A].to_vec();
        let window_len = NonZeroUsize::new(1).unwrap();
        let max_window_expansions = None;
        let mut windows = DnaWindows::new(dna, window_len, max_window_expansions);
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
    fn unambiguous_dna_windows_reference_implementation(
        dna: &[Nucleotide],
        window_len: NonZeroUsize,
    ) -> HashSet<(Range<usize>, Vec<Nucleotide>)> {
        dna.windows(window_len.get())
            .map(|window| Canonical::new(window.iter().copied()).collect())
            .enumerate()
            .map(|(i, window)| (i..i + window_len.get(), window))
            .collect()
    }

    // Slightly more complicated reference implementation for handling ambiguities
    fn dna_windows_reference_implementation(
        dna: &[NucleotideAmbiguous],
        window_len: NonZeroUsize,
        max_window_expansions: Option<NonZeroUsize>,
    ) -> HashSet<(Range<usize>, Vec<Nucleotide>)> {
        let mut items: HashSet<(Range<usize>, Vec<Nucleotide>)> = HashSet::new();
        for (i, window) in dna.windows(window_len.get()).enumerate() {
            let expansions = Expansions::new(window);
            if let Some(limit) = max_window_expansions {
                if expansions.size_hint().0 > limit.get() {
                    continue;
                }
            }
            for expansion in expansions {
                let canonical = Canonical::new(expansion.iter().copied()).collect();
                items.insert((i..i + window_len.get(), canonical));
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

        let actual = DnaWindows::new(dna.clone(), window_len, max_window_expansions);

        // If there are too many windows to evaluate, we can't safely guage if things match.
        if actual.size_hint().0 > MAX_ITER_LEN {
            return true;
        }

        let actual: HashSet<_> = actual.map(|(i, w)| (i, w.to_vec())).collect();

        let reference =
            dna_windows_reference_implementation(&dna, window_len, max_window_expansions);

        actual == reference
    }

    quickcheck! {
        fn unambiguous_windows_match_reference_implementation(
            dna: Vec<Nucleotide>,
            window_len: WindowLen,
            max_window_expansions: Option<NonZeroUsize>
        ) -> bool {
            let window_len = window_len.for_slice(&dna);

            let reference1 = unambiguous_dna_windows_reference_implementation(&dna, window_len);

            let dna: Vec<_> = dna.into_iter().map(NucleotideAmbiguous::from).collect();
            let reference2 = dna_windows_reference_implementation(&dna, window_len, max_window_expansions);

            let actual = DnaWindows::new(dna, window_len, max_window_expansions);
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
            let size_hint = DnaWindows::new(dna, window_len, max_window_expansions).size_hint();
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
            let mut windows = DnaWindows::new(dna.0, window_len, max_window_expansions);
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
            let mut windows = DnaWindows::new(dna.0, window_len, max_window_expansions).map(|(i, _)| i.start);
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
