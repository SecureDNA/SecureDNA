// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use quickdna::{NucleotideIter, NucleotideLike, ToNucleotideLike, TranslationTable};

pub const DNA_WINDOW_LEN: usize = shared_types::WINDOW_LENGTH_DNA_NORMAL;
pub const RUNT_WINDOW_LEN: usize = shared_types::WINDOW_LENGTH_DNA_RUNT;
pub const PROTEIN_WINDOW_LEN: usize = shared_types::WINDOW_LENGTH_AA;

/// Provides iter of windows with default sizes
#[derive(Clone, Debug, Default)]
pub struct Windows {
    dna_windows: DnaWindows,
    // We need these because DNA and runts share the same DnaWindows
    include_dna: bool,
    include_runts: bool,
    protein_windows: ProteinWindows,
}

impl Windows {
    /// Provides all available windows
    pub fn from_dna<D, I, N>(dna: D) -> Self
    where
        D: IntoIterator<IntoIter = I>,
        I: DoubleEndedIterator<Item = N> + ExactSizeIterator + Clone,
        N: ToNucleotideLike,
    {
        WindowsBuilder::everything().build_from_dna(dna)
    }

    /// Provides builder where only specified things are included
    pub fn builder() -> WindowsBuilder {
        WindowsBuilder::default()
    }

    /// Returns an iterator over the windows and their original position in the full FASTA
    ///
    /// The indexes returned by `enumerate_windows` are not strictly
    /// monotonically increasing because the current implementation (e.g.)
    /// yields all forward DNA windows before all RC DNA windows.
    pub fn enumerate_windows(&self) -> impl ExactSizeIterator<Item = (usize, &str)> {
        // TODO: simplify when const Default becomes available
        static EMPTY: DnaWindows = DnaWindows {
            dna: String::new(),
            dna_rc: String::new(),
        };

        let dna_windows = if self.include_dna {
            &self.dna_windows
        } else {
            &EMPTY
        }
        .enumerate_windows(DNA_WINDOW_LEN);

        let runt_windows = if self.include_runts {
            &self.dna_windows
        } else {
            &EMPTY
        }
        .enumerate_windows(RUNT_WINDOW_LEN);

        let protein_windows = self.protein_windows.enumerate_windows(PROTEIN_WINDOW_LEN);

        WithExactSize(dna_windows.chain(runt_windows).chain(protein_windows))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsBuilder {
    include_dna: bool,
    include_runts: bool,
    include_proteins: bool,
}

impl WindowsBuilder {
    pub fn everything() -> Self {
        Self {
            include_dna: true,
            include_runts: true,
            include_proteins: true,
        }
    }

    pub fn include_dna(&mut self, value: bool) -> &mut Self {
        self.include_dna = value;
        self
    }

    pub fn include_runts(&mut self, value: bool) -> &mut Self {
        self.include_runts = value;
        self
    }

    pub fn include_proteins(&mut self, value: bool) -> &mut Self {
        self.include_proteins = value;
        self
    }

    pub fn build_from_dna<D, I, N>(&self, dna: D) -> Windows
    where
        D: IntoIterator<IntoIter = I>,
        I: DoubleEndedIterator<Item = N> + ExactSizeIterator + Clone,
        N: ToNucleotideLike,
    {
        let iter = dna.into_iter();
        let include_dna = self.include_dna;
        let include_runts = self.include_runts;
        let include_proteins = self.include_proteins;

        let dna_windows = (include_dna || include_runts)
            .then(|| DnaWindows::from_dna(iter.clone()))
            .unwrap_or_default();
        let protein_windows = include_proteins
            .then(|| ProteinWindows::from_dna(iter))
            .unwrap_or_default();

        Windows {
            dna_windows,
            include_dna,
            include_runts,
            protein_windows,
        }
    }
}

/// Provides iterator of nucleotide windows of supplied DNA.
#[derive(Clone, Debug, Default)]
pub struct DnaWindows {
    dna: String,
    dna_rc: String,
}

impl DnaWindows {
    pub fn from_dna<D, I, N>(dna: D) -> Self
    where
        D: IntoIterator<IntoIter = I>,
        I: DoubleEndedIterator<Item = N> + Clone,
        N: ToNucleotideLike,
    {
        let dna = dna.into_iter();

        let dna_rc = dna
            .clone()
            .reverse_complement()
            .map(|n| n.to_nucleotide_like().to_ascii())
            .collect();
        let dna_rc = String::from_utf8(dna_rc).unwrap();

        let dna = dna.map(|n| n.to_nucleotide_like().to_ascii()).collect();
        let dna = String::from_utf8(dna).unwrap();

        Self { dna, dna_rc }
    }

    /// Returns an iterator over the windows and their original position in the full FASTA
    ///
    /// The indexes returned by `enumerate_windows` are not strictly
    /// monotonically increasing because the current implementation (e.g.)
    /// yields all forward windows before all RC windows.
    pub fn enumerate_windows(
        &self,
        window_len: usize,
    ) -> impl ExactSizeIterator<Item = (usize, &str)> {
        let forward_windows = ascii_str_windows(&self.dna, window_len).enumerate();
        let rc_windows = ascii_str_windows(&self.dna_rc, window_len)
            .rev()
            .enumerate();
        WithExactSize(forward_windows.chain(rc_windows))
    }
}

/// Provides iterator of amino acids windows of supplied DNA.
#[derive(Clone, Debug, Default)]
pub struct ProteinWindows {
    aas: [String; 3],
    aas_rc: [String; 3],
}

impl ProteinWindows {
    pub fn from_dna<D, I, N>(dna: D) -> Self
    where
        D: IntoIterator<IntoIter = I>,
        I: DoubleEndedIterator<Item = N> + ExactSizeIterator + Clone,
        N: ToNucleotideLike,
    {
        let mut dna = dna.into_iter();
        let frames = std::array::from_fn(|_| {
            let iter = dna.clone().trimmed_to_codon();
            let _ = dna.next();
            iter
        });

        let ncbi1 = TranslationTable::Ncbi1.to_fn();
        let aas = frames.clone().map(|frame| {
            let translated: Vec<_> = frame.codons().map(ncbi1).collect();
            String::from_utf8(translated).unwrap()
        });
        let aas_rc = frames.map(|frame| {
            let translated: Vec<_> = frame.reverse_complement().codons().map(ncbi1).collect();
            String::from_utf8(translated).unwrap()
        });

        Self { aas, aas_rc }
    }

    /// Returns an iterator over the windows and their original position in the full FASTA
    ///
    /// The indexes returned by `enumerate_windows` are not strictly
    /// monotonically increasing because the current implementation (e.g.)
    /// yields all forward frame 0 windows before all RC frame 0 windows.
    pub fn enumerate_windows(
        &self,
        aa_window_len: usize,
    ) -> impl ExactSizeIterator<Item = (usize, &str)> {
        let forward_aas = |offset: usize| {
            ascii_str_windows(&self.aas[offset], aa_window_len)
                .enumerate()
                .map(move |(i, w)| (offset + 3 * i, w))
        };
        let reverse_aas = |offset: usize| {
            ascii_str_windows(&self.aas_rc[offset], aa_window_len)
                .rev()
                .enumerate()
                .map(move |(i, w)| (offset + 3 * i, w))
        };

        WithExactSize(
            // Deliberately using chain instead of flat_map for accurate size_hints
            forward_aas(0)
                .chain(forward_aas(1))
                .chain(forward_aas(2))
                .chain(reverse_aas(0))
                .chain(reverse_aas(1))
                .chain(reverse_aas(2)),
        )
    }
}

// Unfortunate, but needed as long as we're using strings, AFAICT
fn ascii_str_windows(
    data: &str,
    window_len: usize,
) -> impl DoubleEndedIterator<Item = &str> + ExactSizeIterator {
    let num_windows = data.as_bytes().windows(window_len).len();
    (0..num_windows).map(move |i| &data[i..i + window_len])
}

// Workaround for chains not having exact sizes even if they wouldn't overflow.
struct WithExactSize<I>(I);

impl<I: Iterator> Iterator for WithExactSize<I> {
    type Item = I::Item;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<I: Iterator> ExactSizeIterator for WithExactSize<I> {}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use quickcheck::quickcheck;
    use quickdna::{BaseSequence, DnaSequence, Nucleotide};

    use super::*;

    macro_rules! assert_contains {
        ($set:expr, $value:expr) => {
            let set = &$set;
            let value = &$value;
            assert!(set.contains(value), "{value:?} not in {set:?}");
        };
    }

    fn to_dna(repr: &str) -> Vec<Nucleotide> {
        let dna: DnaSequence<Nucleotide> = repr.parse().unwrap();
        dna.as_slice().to_owned()
    }

    fn expected_dna_windows(dna: &[Nucleotide], window_len: usize) -> HashSet<(usize, String)> {
        let mut expected = HashSet::new();

        for (frame_idx, window) in dna.windows(window_len).enumerate() {
            let window_dna = DnaSequence::<Nucleotide>::new(window.to_vec());
            expected.insert((frame_idx, window_dna.to_string()));
            expected.insert((frame_idx, window_dna.reverse_complement().to_string()));
        }

        expected
    }

    fn expected_protein_windows(dna: &[Nucleotide], window_len: usize) -> HashSet<(usize, String)> {
        let mut expected = HashSet::new();
        let ncbi1 = TranslationTable::Ncbi1;

        for (frame_idx, window) in dna.windows(3 * window_len).enumerate() {
            let window_dna = DnaSequence::<Nucleotide>::new(window.to_vec());
            expected.insert((frame_idx, window_dna.translate(ncbi1).to_string()));
            expected.insert((
                frame_idx,
                window_dna.reverse_complement().translate(ncbi1).to_string(),
            ));
        }

        expected
    }

    #[test]
    fn smoke_test() {
        let dna = to_dna(
            "ATGAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATCGTCCCGTCAGGCCCCCTC\
             AAAGCCGAGATCGCGCAGAGACTTGAAGATGTCTTTGCAGGGAAGAACACCGATCTTGAG",
        );

        let windows = Windows::from_dna(dna);

        let vals: HashSet<_> = windows.enumerate_windows().collect();

        // Windows starting at the first 4 nucleotides

        assert_contains!(vals, (0, "ATGAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATC")); // DNA
        assert_contains!(vals, (0, "GATAGAGAGAACGTACGTTTCGACCTCGGTTAAAAGACTCAT")); // RC DNA
        assert_contains!(vals, (0, "ATGAGTCTTTTAACCGAGGTCGAAACGTAC")); // Runt DNA
        assert_contains!(vals, (0, "GTACGTTTCGACCTCGGTTAAAAGACTCAT")); // Runt RC DNA
        assert_contains!(vals, (0, "MSLLTEVETYVLSIVPSGPL")); // AA
        assert_contains!(vals, (0, "EGA*RDDRENVRFDLG*KTH")); // RC AA

        assert_contains!(vals, (1, "TGAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATCG")); // DNA
        assert_contains!(vals, (1, "CGATAGAGAGAACGTACGTTTCGACCTCGGTTAAAAGACTCA")); // RC DNA
        assert_contains!(vals, (1, "TGAGTCTTTTAACCGAGGTCGAAACGTACG")); // Runt DNA
        assert_contains!(vals, (1, "CGTACGTTTCGACCTCGGTTAAAAGACTCA")); // Runt RC DNA
        assert_contains!(vals, (1, "*VF*PRSKRTFSLSSRQAPS")); // AA
        assert_contains!(vals, (1, "*GGLTGR*RERTFRPRLKDS")); // RC AA

        assert_contains!(vals, (2, "GAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATCGT")); // DNA
        assert_contains!(vals, (2, "ACGATAGAGAGAACGTACGTTTCGACCTCGGTTAAAAGACTC")); // RC DNA
        assert_contains!(vals, (2, "GAGTCTTTTAACCGAGGTCGAAACGTACGT")); // Runt DNA
        assert_contains!(vals, (2, "ACGTACGTTTCGACCTCGGTTAAAAGACTC")); // Runt RC DNA
        assert_contains!(vals, (2, "ESFNRGRNVRSLYRPVRPPQ")); // AA
        assert_contains!(vals, (2, "LRGPDGTIERTYVSTSVKRL")); // RC AA

        assert_contains!(vals, (3, "AGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATCGTC")); // DNA
        assert_contains!(vals, (3, "GACGATAGAGAGAACGTACGTTTCGACCTCGGTTAAAAGACT")); // RC DNA
        assert_contains!(vals, (3, "AGTCTTTTAACCGAGGTCGAAACGTACGTT")); // Runt DNA
        assert_contains!(vals, (3, "AACGTACGTTTCGACCTCGGTTAAAAGACT")); // Runt RC DNA
        assert_contains!(vals, (3, "SLLTEVETYVLSIVPSGPLK")); // AA
        assert_contains!(vals, (3, "FEGA*RDDRENVRFDLG*KT")); // RC AA

        // The last 4 AA windows

        assert_contains!(vals, (57, "LKAEIAQRLEDVFAGKNTDL")); // AA
        assert_contains!(vals, (57, "KIGVLPCKDIFKSLRDLGFE")); // RC AA

        assert_contains!(vals, (58, "SKPRSRRDLKMSLQGRTPIL")); // AA
        assert_contains!(vals, (58, "QDRCSSLQRHLQVSARSRL*")); // RC AA

        assert_contains!(vals, (59, "QSRDRAET*RCLCREEHRS*")); // AA
        assert_contains!(vals, (59, "SRSVFFPAKTSSSLCAISAL")); // RC AA

        assert_contains!(vals, (60, "KAEIAQRLEDVFAGKNTDLE")); // AA
        assert_contains!(vals, (60, "LKIGVLPCKDIFKSLRDLGF")); // RC AA

        // The last 4 DNA windows

        assert_contains!(vals, (75, "CAGAGACTTGAAGATGTCTTTGCAGGGAAGAACACCGATCTT")); // DNA
        assert_contains!(vals, (75, "AAGATCGGTGTTCTTCCCTGCAAAGACATCTTCAAGTCTCTG")); // RC DNA

        assert_contains!(vals, (76, "AGAGACTTGAAGATGTCTTTGCAGGGAAGAACACCGATCTTG")); // DNA
        assert_contains!(vals, (76, "CAAGATCGGTGTTCTTCCCTGCAAAGACATCTTCAAGTCTCT")); // RC DNA

        assert_contains!(vals, (77, "GAGACTTGAAGATGTCTTTGCAGGGAAGAACACCGATCTTGA")); // DNA
        assert_contains!(vals, (77, "TCAAGATCGGTGTTCTTCCCTGCAAAGACATCTTCAAGTCTC")); // RC DNA

        assert_contains!(vals, (78, "AGACTTGAAGATGTCTTTGCAGGGAAGAACACCGATCTTGAG")); // DNA
        assert_contains!(vals, (78, "CTCAAGATCGGTGTTCTTCCCTGCAAAGACATCTTCAAGTCT")); // RC DNA

        // The last 4 runt DNA windows

        assert_contains!(vals, (87, "GATGTCTTTGCAGGGAAGAACACCGATCTT")); // Runt DNA
        assert_contains!(vals, (87, "AAGATCGGTGTTCTTCCCTGCAAAGACATC")); // Runt RC DNA

        assert_contains!(vals, (88, "ATGTCTTTGCAGGGAAGAACACCGATCTTG")); // Runt DNA
        assert_contains!(vals, (88, "CAAGATCGGTGTTCTTCCCTGCAAAGACAT")); // Runt RC DNA

        assert_contains!(vals, (89, "TGTCTTTGCAGGGAAGAACACCGATCTTGA")); // Runt DNA
        assert_contains!(vals, (89, "TCAAGATCGGTGTTCTTCCCTGCAAAGACA")); // Runt RC DNA

        assert_contains!(vals, (90, "GTCTTTGCAGGGAAGAACACCGATCTTGAG")); // Runt DNA
        assert_contains!(vals, (90, "CTCAAGATCGGTGTTCTTCCCTGCAAAGAC")); // Runt RC DNA

        assert_eq!(
            vals.len(),
            // The full DNA above should have a length of 120.
            // For DNA windows: after the first 42 bp window there should be 78 more bps, each of
            // which allows another window to exist, for a total of 79 windows.
            79
            // For runts: after the first 30 bp window there should be 90 more bps, each of which
            // allows another window to exist, for a total of 91 windows
            + 91
            // For protein windows: A protein window is 20 aa or 60 bp, after which there are
            // 60 more bp, for a total 61 windows.
            + 61
            // RC doesn't change DNA length, so the number of RC windows should be the same.
            + 79 + 91 + 61
        );
    }

    #[test]
    fn expected_windows() {
        let dna = to_dna(
            "ATGAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATCGTCCCGTCAGGCCCCCTC\
             AAAGCCGAGATCGCGCAGAGACTTGAAGATGTCTTTGCAGGGAAGAACACCGATCTTGAG",
        );

        let windows = Windows::from_dna(&dna);
        let enumerated = windows.enumerate_windows();

        assert_eq!(
            enumerated.len(),
            2 * (dna.len() - DNA_WINDOW_LEN + 1)
                + 2 * (dna.len() - RUNT_WINDOW_LEN + 1)
                + 2 * (dna.len() - 3 * PROTEIN_WINDOW_LEN + 1)
        );

        let actual = enumerated
            .map(|(idx, value)| (idx, value.to_owned()))
            .collect::<HashSet<(usize, String)>>();

        let expected = &(&expected_dna_windows(&dna, DNA_WINDOW_LEN)
            | &expected_dna_windows(&dna, RUNT_WINDOW_LEN))
            | &expected_protein_windows(&dna, PROTEIN_WINDOW_LEN);

        // Note: assert_eq! produces overwhelming failure messages; this shows helpful diffs
        let missing = &expected - &actual;
        assert!(missing.is_empty(), "missing (index, window)s: {missing:?}");
        let unexpected = &actual - &expected;
        assert!(
            unexpected.is_empty(),
            "unexpected (index, window)s: {unexpected:?}"
        );
    }

    #[test]
    fn windows_convenience_functions() {
        let protein_window_len = 20;

        {
            let dna = to_dna(
                "ATGAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATCGTCCCGTCAGGCCCCCTC\
                 AAAGCCGAGATCGCGCAGAGACTTGAAGATGTCTTTGCAGGGAAGAACACCGATCTTGAG",
            );

            let windows = Windows::from_dna(&dna);
            let enumerated = windows.enumerate_windows();
            let protein_windows = ProteinWindows::from_dna(&dna);
            let enumerated_protein_windows = protein_windows.enumerate_windows(protein_window_len);

            assert_eq!(enumerated_protein_windows.len(), 122);
            assert_eq!(enumerated.len(), 462);
        }

        {
            let dna = to_dna("ATG");

            let windows = Windows::from_dna(&dna);
            let enumerated = windows.enumerate_windows();
            let protein_windows = ProteinWindows::from_dna(&dna);
            let enumerated_protein_windows = protein_windows.enumerate_windows(protein_window_len);

            assert_eq!(enumerated_protein_windows.len(), 0);
            assert_eq!(enumerated.len(), 0);
        }

        {
            let dna = to_dna("ATGAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATC");

            let windows = Windows::from_dna(dna);
            let enumerated = windows.enumerate_windows();

            assert_eq!(enumerated.len(), 28);
        }
    }

    #[test]
    #[should_panic]
    fn test_dna_windows_cannot_have_zero_len() {
        let dna = to_dna("CATTAG");
        let window_len = 0;
        let windows = DnaWindows::from_dna(dna.as_slice());
        windows.enumerate_windows(window_len).count();
    }

    #[test]
    #[should_panic]
    fn test_protein_windows_cannot_have_zero_len() {
        let dna = to_dna("CATTAGATCG");
        let window_len = 0;
        let windows = ProteinWindows::from_dna(dna);
        windows.enumerate_windows(window_len).count();
    }

    #[test]
    fn test_windows_len_can_be_calculated() {
        let dna = to_dna("CATTAGCATTAGCATTAGCATTAGCATTAGCATTAGCATTAGCATTAGCATTAGCATTAGCATTAG");

        // In order for this test to be useful...
        assert!(dna.len() > DNA_WINDOW_LEN);
        assert!(dna.len() > RUNT_WINDOW_LEN);
        assert!(dna.len() > 3 * PROTEIN_WINDOW_LEN);

        // When dna.len() == DNA_WINDOW_LEN, there is one DNA window per direction,
        // but each additional BP adds another window.
        let num_dna_windows_per_direction = 1 + dna.len() - DNA_WINDOW_LEN;

        // Same logic applies to runts...
        let num_runt_windows_per_direction = 1 + dna.len() - RUNT_WINDOW_LEN;

        // Each amino acid in the returned protein window corresponds with 3 BPs in the source DNA
        // so there's 1 window when dna.len() == 3 * PROTEIN_WINDOW_LEN, and each additional BP
        // adds another window (because there are multiple reading frames)
        let num_protein_windows_per_direction = 1 + dna.len() - 3 * PROTEIN_WINDOW_LEN;

        let num_directions = 2; // forward and RC

        let expected_num_windows = num_directions
            * (num_dna_windows_per_direction
                + num_runt_windows_per_direction
                + num_protein_windows_per_direction);

        let windows = Windows::from_dna(dna);

        // Doing this to make sure the WithExactSize wrapper works.
        let len = windows.enumerate_windows().len();
        assert_eq!(len, expected_num_windows);
    }

    #[test]
    fn test_dna_windows_len_can_be_calculated() {
        let dna = to_dna("CATTAG");
        let window_len = 3;
        let windows = DnaWindows::from_dna(dna);

        // Doing this to make sure the WithExactSize wrapper works.
        let len = windows.enumerate_windows(window_len).len();
        assert_eq!(len, 8); // 4 forward, 4 rc
    }

    #[test]
    fn test_protein_windows_len_can_be_calculated() {
        let dna = to_dna("CATTAGATCG");
        let window_len = 2;
        let windows = ProteinWindows::from_dna(dna);

        // Doing this to make sure the WithExactSize wrapper works.
        let len = windows.enumerate_windows(window_len).len();
        assert_eq!(len, 10); // 5 forward, 5 rc
    }

    quickcheck! {

        fn windows_matches_reference_implementation(dna: Vec<Nucleotide>) -> bool {
            let windows = Windows::from_dna(&dna);

            let actual: HashSet<_> = windows
                .enumerate_windows()
                .map(|(idx, value)| (idx, value.to_owned()))
                .collect();

            let expected = &(&expected_dna_windows(&dna, DNA_WINDOW_LEN)
                | &expected_dna_windows(&dna, RUNT_WINDOW_LEN))
                | &expected_protein_windows(&dna, PROTEIN_WINDOW_LEN);

            actual == expected
        }

        fn windows_with_only_dna_matches_reference_implementation(dna: Vec<Nucleotide>) -> bool {
            let windows = Windows::builder().include_dna(true).build_from_dna(&dna);

            let actual: HashSet<_> = windows
                .enumerate_windows()
                .map(|(idx, value)| (idx, value.to_owned()))
                .collect();

            let expected = expected_dna_windows(&dna, DNA_WINDOW_LEN);

            actual == expected
        }

        fn windows_with_only_runts_matches_reference_implementation(dna: Vec<Nucleotide>) -> bool {
            let windows = Windows::builder().include_runts(true).build_from_dna(&dna);

            let actual: HashSet<_> = windows
                .enumerate_windows()
                .map(|(idx, value)| (idx, value.to_owned()))
                .collect();

            let expected = expected_dna_windows(&dna, RUNT_WINDOW_LEN);

            actual == expected
        }

        fn windows_with_only_proteins_matches_reference_implementation(dna: Vec<Nucleotide>) -> bool {
            let windows = Windows::builder().include_proteins(true).build_from_dna(&dna);

            let actual: HashSet<_> = windows
                .enumerate_windows()
                .map(|(idx, value)| (idx, value.to_owned()))
                .collect();

            let expected = expected_protein_windows(&dna, PROTEIN_WINDOW_LEN);

            actual == expected
        }

        fn dna_windows_matches_reference_implementation(dna: Vec<Nucleotide>) -> bool {
            let window_len = 42;
            let windows = DnaWindows::from_dna(&dna);

            let actual: HashSet<_> = windows
                .enumerate_windows(window_len)
                .map(|(idx, value)| (idx, value.to_owned()))
                .collect();

            let expected = expected_dna_windows(&dna, window_len);

            actual == expected
        }

        fn protein_windows_matches_reference_implementation(dna: Vec<Nucleotide>) -> bool {
            let window_len = 20;
            let windows = ProteinWindows::from_dna(&dna);

            let actual: HashSet<_> = windows
                .enumerate_windows(window_len)
                .map(|(idx, value)| (idx, value.to_owned()))
                .collect();

            let expected = expected_protein_windows(&dna, window_len);

            actual == expected
        }
    }
}
