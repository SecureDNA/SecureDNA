// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::Arc;

use quickdna::{NucleotideAmbiguous, NucleotideIter, TranslationTable};
use shared_types::hash::HashDirection;

use super::expansions::WindowExpansions;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Forward,
    ReverseComplement,
}

impl From<Direction> for HashDirection {
    fn from(value: Direction) -> Self {
        match value {
            Direction::Forward => HashDirection::FW,
            Direction::ReverseComplement => HashDirection::RC,
        }
    }
}

impl TryFrom<HashDirection> for Direction {
    type Error = HashDirection;

    fn try_from(value: HashDirection) -> Result<Self, Self::Error> {
        match value {
            HashDirection::FW => Ok(Direction::Forward),
            HashDirection::RC => Ok(Direction::ReverseComplement),
            x => Err(x),
        }
    }
}

/// Iterator of amino acid windows of supplied DNA.
#[derive(Clone)]
pub struct AaWindows {
    windows: WindowExpansions,
    // Whether to return forward or reverse complement windows.
    direction: Direction,
}

/// Amino acid window
///
/// Note that there is no amino acid type yet, so this holds a [`str`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AaWindow(String);

impl AaWindows {
    /// Creates a new iterator of DNA windows translated into amino acids.
    ///
    /// Given a sequence of `src` DNA, the iterator yields `(index, direction, translation)`
    /// triplets, where each `translation` is a window of nucleotides mapped through NCBI1,
    /// producing a window that's `aa_window_len` amino acids long.
    ///
    /// Ambiguous DNA is not yet truly supported; this blindly maps through NCBI1 and may
    /// produce unambiguous amino acids whenever ambiguity cannot affect the outcome, but
    /// otherwise will produce invalid results.
    ///
    /// Windows are yielded in ascending order of `index`, but beyond that no particular order
    /// is promised.
    pub fn new(
        src: Arc<[NucleotideAmbiguous]>,
        aa_window_len: NonZeroUsize,
        max_window_expansions: Option<NonZeroUsize>,
        direction: Direction,
    ) -> Self {
        assert!(src.len() < usize::MAX / 2);

        // TODO: Does the client trust the HDB? If not, perhaps we should consider
        // the possibility that  aa_window_len is unreasonable.
        let nuc_window_len = aa_window_len
            .checked_mul(NonZeroUsize::new(3).unwrap())
            .expect("aa_window_len must be smaller than 1/3rd of usize::MAX");
        let windows = WindowExpansions::new(src, nuc_window_len, max_window_expansions);

        Self { windows, direction }
    }
}

impl Iterator for AaWindows {
    type Item = (Range<usize>, AaWindow);

    fn next(&mut self) -> Option<Self::Item> {
        let (indexes, nucs) = self.windows.next()?;
        let ncbi1 = TranslationTable::Ncbi1.to_fn();
        let translated = match self.direction {
            Direction::Forward => nucs.iter().codons().map(ncbi1).collect(),
            Direction::ReverseComplement => nucs
                .iter()
                .reverse_complement()
                .codons()
                .map(ncbi1)
                .collect(),
        };
        let window = AaWindow(String::from_utf8(translated).unwrap());
        Some((indexes, window))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.windows.size_hint()
    }
}

impl std::ops::Deref for AaWindow {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for AaWindow {
    fn as_ref(&self) -> &str {
        self
    }
}

impl std::cmp::PartialEq<AaWindow> for &str {
    fn eq(&self, other: &AaWindow) -> bool {
        *self == other.as_ref()
    }
}

impl std::cmp::PartialEq<&str> for AaWindow {
    fn eq(&self, other: &&str) -> bool {
        self.as_ref() == *other
    }
}

impl std::fmt::Debug for AaWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_tuple("AaWindow").field(self).finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::HashSet;

    use quickcheck::{quickcheck, Arbitrary, Gen};

    use quickdna::{BaseSequence, DnaSequence, Nucleotide};

    fn to_dna(repr: &str) -> Vec<Nucleotide> {
        let dna: DnaSequence<Nucleotide> = repr.parse().unwrap();
        dna.as_slice().to_owned()
    }

    fn to_dna_amb(repr: &str) -> Vec<NucleotideAmbiguous> {
        let dna: DnaSequence<NucleotideAmbiguous> = repr.parse().unwrap();
        dna.as_slice().to_owned()
    }

    fn to_amb_arc(dna: &[Nucleotide]) -> Arc<[NucleotideAmbiguous]> {
        dna.iter().copied().map(NucleotideAmbiguous::from).collect()
    }

    #[test]
    fn smoke_test() {
        let dna = to_dna("ACCAGGAGAGAGTGTTGTGTGTGATCCCGG"); // 30 nucleotides
        let window_len = NonZeroUsize::new(8).unwrap();
        // I expect the above sequence to have the following 8-AA/24-nucleotide windows:
        // ACC AGG AGA GAG TGT TGT GTG TGA
        // CCA GGA GAG AGT GTT GTG TGT GAT
        // CAG GAG AGA GTG TTG TGT GTG ATC
        // AGG AGA GAG TGT TGT GTG TGA TCC
        // GGA GAG AGT GTT GTG TGT GAT CCC
        // GAG AGA GTG TTG TGT GTG ATC CCG
        // AGA GAG TGT TGT GTG TGA TCC CGG

        let expected_fw = vec![
            (0..24, "TRRECCV*"),
            (1..25, "PGESVVCD"),
            (2..26, "QERVLCVI"),
            (3..27, "RRECCV*S"),
            (4..28, "GESVVCDP"),
            (5..29, "ERVLCVIP"),
            (6..30, "RECCV*SR"),
        ];
        let expected_rc = vec![
            (0..24, "SHTTLSPG"),
            (1..25, "ITHNTLSW"),
            (2..26, "DHTQHSLL"),
            (3..27, "GSHTTLSP"),
            (4..28, "GITHNTLS"),
            (5..29, "RDHTQHSL"),
            (6..30, "PGSHTTLS"),
        ];

        let max_window_expansions = Some(NonZeroUsize::MIN);

        // Testing out DNA with length divisible by 3
        let windows_fw = AaWindows::new(
            to_amb_arc(&dna[..30]),
            window_len,
            max_window_expansions,
            Direction::Forward,
        );
        assert_eq!(windows_fw.size_hint(), (7, Some(7)));
        let actual: Vec<_> = windows_fw.collect();
        let actual: Vec<_> = actual
            .iter()
            .map(|(i, w)| (i.clone(), w.as_ref()))
            .collect();
        assert_eq!(actual, expected_fw);

        let windows_rc = AaWindows::new(
            to_amb_arc(&dna[..30]),
            window_len,
            max_window_expansions,
            Direction::ReverseComplement,
        );
        assert_eq!(windows_rc.size_hint(), (7, Some(7)));
        let actual: Vec<_> = windows_rc.collect();
        let actual: Vec<_> = actual
            .iter()
            .map(|(i, w)| (i.clone(), w.as_ref()))
            .collect();
        assert_eq!(actual, expected_rc);

        let windows_fw = AaWindows::new(
            to_amb_arc(&dna[..29]),
            window_len,
            max_window_expansions,
            Direction::Forward,
        );
        assert_eq!(windows_fw.size_hint(), (6, Some(6)));
        let actual: Vec<_> = windows_fw.collect();
        let actual: Vec<_> = actual
            .iter()
            .map(|(i, w)| (i.clone(), w.as_ref()))
            .collect();
        assert_eq!(actual, expected_fw[..6]);

        let windows_rc = AaWindows::new(
            to_amb_arc(&dna[..29]),
            window_len,
            max_window_expansions,
            Direction::ReverseComplement,
        );
        assert_eq!(windows_rc.size_hint(), (6, Some(6)));
        let actual: Vec<_> = windows_rc.collect();
        let actual: Vec<_> = actual
            .iter()
            .map(|(i, w)| (i.clone(), w.as_ref()))
            .collect();
        assert_eq!(actual, expected_rc[..6]);

        let windows_fw = AaWindows::new(
            to_amb_arc(&dna[..28]),
            window_len,
            max_window_expansions,
            Direction::Forward,
        );
        assert_eq!(windows_fw.size_hint(), (5, Some(5)));
        let actual: Vec<_> = windows_fw.collect();
        let actual: Vec<_> = actual
            .iter()
            .map(|(i, w)| (i.clone(), w.as_ref()))
            .collect();
        assert_eq!(actual, expected_fw[..5]);

        let windows_rc = AaWindows::new(
            to_amb_arc(&dna[..28]),
            window_len,
            max_window_expansions,
            Direction::ReverseComplement,
        );
        assert_eq!(windows_rc.size_hint(), (5, Some(5)));
        let actual: Vec<_> = windows_rc.collect();
        let actual: Vec<_> = actual
            .iter()
            .map(|(i, w)| (i.clone(), w.as_ref()))
            .collect();
        assert_eq!(actual, expected_rc[..5]);
    }

    #[test]
    fn test_subcodon_dna() {
        let max_window_expansions = Some(NonZeroUsize::MIN);

        for dna in ["", "A", "AA"] {
            for window_len in [1, 2, 3, 4, 5, 10, 20] {
                let window_len = NonZeroUsize::new(window_len).unwrap();
                let mut windows = AaWindows::new(
                    to_amb_arc(&to_dna(dna)),
                    window_len,
                    max_window_expansions,
                    Direction::Forward,
                );
                assert_eq!(
                    windows.size_hint(),
                    (0, Some(0)),
                    "size_hint should be empty for dna={dna:?} window_len={window_len}"
                );
                assert!(
                    windows.next().is_none(),
                    "iterator should not produce items for dna={dna:?}, window_len={window_len}"
                );
            }
        }
    }

    #[test]
    fn smoke_test_ambiguous_aa_windows() {
        let dna = to_dna_amb("ATNARTCTTTTAACGHAGGT"); // len = 20

        let window_len = NonZeroUsize::new(5).unwrap();
        let max_window_expansions = None;
        let windows = AaWindows::new(
            dna.into(),
            window_len,
            max_window_expansions,
            Direction::Forward,
        );

        // I expect the 15-nucleotide windows to look like:
        // offset 0 = ATNARTCTTTTAACG
        // offset 1 = TNARTCTTTTAACGH
        // offset 2 = NARTCTTTTAACGHA
        // offset 3 = ARTCTTTTAACGHAG
        // offset 4 = RTCTTTTAACGHAGG
        // offset 5 = TCTTTTAACGHAGGT

        // Expanding out N = {A, T, C, G} and R = {A, G} and H = {A, T, C}:
        // offset 0 = ATA AAT CTT TTA ACG
        //            ATA AGT CTT TTA ACG
        //            ATT AAT CTT TTA ACG
        //            ATT AGT CTT TTA ACG
        //            ATC AAT CTT TTA ACG
        //            ATC AGT CTT TTA ACG
        //            ATG AAT CTT TTA ACG
        //            ATG AGT CTT TTA ACG
        // offset 1 = TAA ATC TTT TAA CGA
        //            TAA ATC TTT TAA CGT
        //            TAA ATC TTT TAA CGC
        //            TAA GTC TTT TAA CGA
        //            TAA GTC TTT TAA CGT
        //            TAA GTC TTT TAA CGC
        //            TTA ATC TTT TAA CGA
        //            TTA ATC TTT TAA CGT
        //            TTA ATC TTT TAA CGC
        //            TTA GTC TTT TAA CGA
        //            TTA GTC TTT TAA CGT
        //            TTA GTC TTT TAA CGC
        //            TCA ATC TTT TAA CGA
        //            TCA ATC TTT TAA CGT
        //            TCA ATC TTT TAA CGC
        //            TCA GTC TTT TAA CGA
        //            TCA GTC TTT TAA CGT
        //            TCA GTC TTT TAA CGC
        //            TGA ATC TTT TAA CGA
        //            TGA ATC TTT TAA CGT
        //            TGA ATC TTT TAA CGC
        //            TGA GTC TTT TAA CGA
        //            TGA GTC TTT TAA CGT
        //            TGA GTC TTT TAA CGC
        // offset 2 = AAA TCT TTT AAC GAA
        //            AAA TCT TTT AAC GTA
        //            AAA TCT TTT AAC GCA
        //            AAG TCT TTT AAC GAA
        //            AAG TCT TTT AAC GTA
        //            AAG TCT TTT AAC GCA
        //            TAA TCT TTT AAC GAA
        //            TAA TCT TTT AAC GTA
        //            TAA TCT TTT AAC GCA
        //            TAG TCT TTT AAC GAA
        //            TAG TCT TTT AAC GTA
        //            TAG TCT TTT AAC GCA
        //            CAA TCT TTT AAC GAA
        //            CAA TCT TTT AAC GTA
        //            CAA TCT TTT AAC GCA
        //            CAG TCT TTT AAC GAA
        //            CAG TCT TTT AAC GTA
        //            CAG TCT TTT AAC GCA
        //            GAA TCT TTT AAC GAA
        //            GAA TCT TTT AAC GTA
        //            GAA TCT TTT AAC GCA
        //            GAG TCT TTT AAC GAA
        //            GAG TCT TTT AAC GTA
        //            GAG TCT TTT AAC GCA
        // offset 3 = AAT CTT TTA ACG AAG
        //            AAT CTT TTA ACG TAG
        //            AAT CTT TTA ACG CAG
        //            AGT CTT TTA ACG AAG
        //            AGT CTT TTA ACG TAG
        //            AGT CTT TTA ACG CAG
        // offset 4 = ATC TTT TAA CGA AGG
        //            ATC TTT TAA CGT AGG
        //            ATC TTT TAA CGC AGG
        //            GTC TTT TAA CGA AGG
        //            GTC TTT TAA CGT AGG
        //            GTC TTT TAA CGC AGG
        // offset 5 = TCT TTT AAC GAA GGT
        //            TCT TTT AAC GTA GGT
        //            TCT TTT AAC GCA GGT

        // Mapping those through NCBI1 yields:
        let expected: HashSet<(Range<usize>, _)> = [
            (0..15, "INLLT"),
            (0..15, "ISLLT"),
            (0..15, "INLLT"),
            (0..15, "ISLLT"),
            (0..15, "INLLT"),
            (0..15, "ISLLT"),
            (0..15, "MNLLT"),
            (0..15, "MSLLT"),
            (1..16, "*IF*R"),
            (1..16, "*IF*R"),
            (1..16, "*IF*R"),
            (1..16, "*VF*R"),
            (1..16, "*VF*R"),
            (1..16, "*VF*R"),
            (1..16, "LIF*R"),
            (1..16, "LIF*R"),
            (1..16, "LIF*R"),
            (1..16, "LVF*R"),
            (1..16, "LVF*R"),
            (1..16, "LVF*R"),
            (1..16, "SIF*R"),
            (1..16, "SIF*R"),
            (1..16, "SIF*R"),
            (1..16, "SVF*R"),
            (1..16, "SVF*R"),
            (1..16, "SVF*R"),
            (1..16, "*IF*R"),
            (1..16, "*IF*R"),
            (1..16, "*IF*R"),
            (1..16, "*VF*R"),
            (1..16, "*VF*R"),
            (1..16, "*VF*R"),
            (2..17, "KSFNE"),
            (2..17, "KSFNV"),
            (2..17, "KSFNA"),
            (2..17, "KSFNE"),
            (2..17, "KSFNV"),
            (2..17, "KSFNA"),
            (2..17, "*SFNE"),
            (2..17, "*SFNV"),
            (2..17, "*SFNA"),
            (2..17, "*SFNE"),
            (2..17, "*SFNV"),
            (2..17, "*SFNA"),
            (2..17, "QSFNE"),
            (2..17, "QSFNV"),
            (2..17, "QSFNA"),
            (2..17, "QSFNE"),
            (2..17, "QSFNV"),
            (2..17, "QSFNA"),
            (2..17, "ESFNE"),
            (2..17, "ESFNV"),
            (2..17, "ESFNA"),
            (2..17, "ESFNE"),
            (2..17, "ESFNV"),
            (2..17, "ESFNA"),
            (3..18, "NLLTK"),
            (3..18, "NLLT*"),
            (3..18, "NLLTQ"),
            (3..18, "SLLTK"),
            (3..18, "SLLT*"),
            (3..18, "SLLTQ"),
            (4..19, "IF*RR"),
            (4..19, "IF*RR"),
            (4..19, "IF*RR"),
            (4..19, "VF*RR"),
            (4..19, "VF*RR"),
            (4..19, "VF*RR"),
            (5..20, "SFNEG"),
            (5..20, "SFNVG"),
            (5..20, "SFNAG"),
        ]
        .into_iter()
        .map(|(i, w)| (i, w.to_owned()))
        .collect();

        let num_windows = 8 + 24 + 24 + 6 + 6 + 3;
        assert_eq!(windows.size_hint(), (num_windows, Some(num_windows)));
        let windows: HashSet<_> = windows.map(|(i, w)| (i, w.to_string())).collect();

        // Note: assert_eq! produces overwhelming failure messages; this shows helpful diffs
        let missing = &expected - &windows;
        let unexpected = &windows - &expected;
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "missing (index, window)s: {missing:?}\nunexpected (index, window)s: {unexpected:?}"
        );
    }

    #[test]
    fn smoke_test_ambiguous_aa_windows_with_expansion_limit() {
        let dna = to_dna_amb("ATNARTCTTTTAACGHAGGT"); // len = 20

        let window_len = NonZeroUsize::new(5).unwrap();
        let max_window_expansions = Some(NonZeroUsize::new(20).unwrap());
        let windows = AaWindows::new(
            dna.into(),
            window_len,
            max_window_expansions,
            Direction::Forward,
        );

        // I expect the 15-nucleotide windows to look like:
        // offset 0 = ATNARTCTTTTAACG
        // offset 1 = TNARTCTTTTAACGH
        // offset 2 = NARTCTTTTAACGHA
        // offset 3 = ARTCTTTTAACGHAG
        // offset 4 = RTCTTTTAACGHAGG
        // offset 5 = TCTTTTAACGHAGGT

        // Expanding out N = {A, C, T, G} and R = {A, G} and H = {A, C, T}
        // offset 0 = ATA AAT CTT TTA ACG
        //            ATA AGT CTT TTA ACG
        //            ATT AAT CTT TTA ACG
        //            ATT AGT CTT TTA ACG
        //            ATC AAT CTT TTA ACG
        //            ATC AGT CTT TTA ACG
        //            ATG AAT CTT TTA ACG
        //            ATG AGT CTT TTA ACG
        // offset 1 = skipped due to having 24 expansions
        // offset 2 = skipped due to having 24 expansions
        // offset 3 = AAT CTT TTA ACG AAG
        //            AAT CTT TTA ACG TAG
        //            AAT CTT TTA ACG CAG
        //            AGT CTT TTA ACG AAG
        //            AGT CTT TTA ACG TAG
        //            AGT CTT TTA ACG CAG
        // offset 4 = ATC TTT TAA CGA AGG
        //            ATC TTT TAA CGT AGG
        //            ATC TTT TAA CGC AGG
        //            GTC TTT TAA CGA AGG
        //            GTC TTT TAA CGT AGG
        //            GTC TTT TAA CGC AGG
        // offset 5 = TCT TTT AAC GAA GGT
        //            TCT TTT AAC GTA GGT
        //            TCT TTT AAC GCA GGT

        // Mapping those through NCBI1 yields:
        let expected: HashSet<(Range<usize>, _)> = [
            (0..15, "INLLT"),
            (0..15, "ISLLT"),
            (0..15, "INLLT"),
            (0..15, "ISLLT"),
            (0..15, "INLLT"),
            (0..15, "ISLLT"),
            (0..15, "MNLLT"),
            (0..15, "MSLLT"),
            (3..18, "NLLTK"),
            (3..18, "NLLT*"),
            (3..18, "NLLTQ"),
            (3..18, "SLLTK"),
            (3..18, "SLLT*"),
            (3..18, "SLLTQ"),
            (4..19, "IF*RR"),
            (4..19, "IF*RR"),
            (4..19, "IF*RR"),
            (4..19, "VF*RR"),
            (4..19, "VF*RR"),
            (4..19, "VF*RR"),
            (5..20, "SFNEG"),
            (5..20, "SFNVG"),
            (5..20, "SFNAG"),
        ]
        .into_iter()
        .map(|(i, w)| (i, w.to_owned()))
        .collect();

        let num_windows = 8 + 6 + 6 + 3;
        assert_eq!(windows.size_hint(), (num_windows, Some(num_windows)));
        let windows: HashSet<_> = windows.map(|(i, w)| (i, w.to_string())).collect();

        // Note: assert_eq! produces overwhelming failure messages; this shows helpful diffs
        let missing = &expected - &windows;
        let unexpected = &windows - &expected;
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "missing (index, window)s: {missing:?}\nunexpected (index, window)s: {unexpected:?}"
        );
    }

    #[derive(Clone, Debug)]
    struct AaWindowLen(usize);

    impl AaWindowLen {
        fn for_slice<T>(&self, slice: &[T]) -> NonZeroUsize {
            // Using len + 1 has two advantages: no div-by-zero and occasionally checking window sizes larger than the data size
            NonZeroUsize::new(1 + self.0 % (slice.len() / 3 + 1)).unwrap()
        }
    }

    impl Arbitrary for AaWindowLen {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(Arbitrary::arbitrary(g))
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(self.0.shrink().map(Self))
        }
    }

    quickcheck! {
        // This checks that the size_hints behave like size hints:
        // they decrement per item, and are 0 when there are no more items.
        fn windows_size_hint_accurately_predicts_length(
            dna: Vec<Nucleotide>,
            window_len: AaWindowLen
        ) -> bool {
            let max_window_expansions = Some(NonZeroUsize::MIN);
            let window_len = window_len.for_slice(&dna);
            let mut windows = AaWindows::new(
                to_amb_arc(&dna),
                window_len,
                max_window_expansions,
                Direction::Forward,
            );
            let (lower, upper) = windows.size_hint();
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
    }
}
