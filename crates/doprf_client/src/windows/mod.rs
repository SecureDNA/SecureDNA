// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers related to generating all windows of a strand of DNA

use std::num::NonZeroUsize;
use std::sync::Arc;

use doprf::tagged::HashTag;
use quickdna::{NucleotideAmbiguous, NucleotideLike, ToNucleotideLike};
use shared_types::hash::{HashDirection, HashSkipType, HashSpec, HashType, HashTypeDescriptor};

mod aa;
mod dna;
mod expansions;

pub use aa::{AaWindow, AaWindows};
pub use dna::{DnaWindow, DnaWindows};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WindowsError {
    #[error("HTD has zero window length: {0:?}")]
    ZeroWindowLength(HashTypeDescriptor),
    #[error("unsupported HTD: {0:?}")]
    UnsupportedHtd(HashTypeDescriptor),
    #[error("non-shingled HTD: {0:?}")]
    NonShingledHtd(HashTypeDescriptor),
    #[error("too many HTDs")]
    TooManyHtds,
}

#[derive(Clone)]
pub struct Windows {
    order_windows: OrderWindows,
    is_at_start: bool,
}

/// Generates [`OrderWindow`]s for many sequences according to a hash-spec obtained from HDB.
///
/// This is similar to concatenating the output of multiple [`SequenceWindows`] together,
/// except that any empty [`SequenceWindows`] will instead produce a single [`OrderWindow::Dummy`].
/// The [`size_hint`](Self::size_hint) will be exact but operates in vaguely linear-time relative
/// to the total length of the DNA sequences. This can be constructed via
/// [`OrderWindows::from_sequences`].
#[derive(Clone)]
pub struct OrderWindows {
    records: Arc<[Arc<[NucleotideAmbiguous]>]>,
    current_record: usize,
    hash_spec: ProcessedHashSpec,
    // Note: this is only None before the first invocation of .next()
    sequence_windows: Option<SequenceWindows>,
}

/// Window and metadata from multiple sequences
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderWindow {
    /// A window and metadata produced from a sequence.
    Real {
        /// Index of record (i.e. sequence) that produced this window.
        record: usize,
        /// Index (in hash spec HTD vector) of Hash-Type Descriptor that specified this window.
        /// This allows determining if a window e.g. contains DNA or amino acids.
        htd_index: u8,
        /// The range of indices in the original DNA that this window was derived from. Some
        /// caveats:
        /// * The length of [`range`](Self::Real::range) may differ from the length of
        ///   [`data`](Self::Real::data) when the window contains amino acids.
        /// * [`range`](Self::Real::range) is not guaranteed to uniformly increment starting
        ///   positions at a steady rate if the DNA sequence is ambiguous. Disambiguation may
        ///   result in multiple windows with the same [`htd_index`](Self::Real::htd_index) and
        ///   [`range`](Self::Real::range). Severe ambiguity may result in sudden jumps/gaps in
        ///   [`range`](Self::Real::range) between windows.
        range: std::ops::Range<usize>,
        /// The actual window data used to produce hashes. This has been disambiguated, and has
        /// any necessary transformations applied to it, such as CECH, RC, NCBI1 DNA-to-AA mapping,
        /// etc, according to the [`htd_index`](Self::Real::htd_index)th HTD.
        data: String,
    },
    /// A placeholder indicating that a particular sequence had no windows.
    /// This can happen if the sequence is too short or too ambiguous.
    /// In this case, we generate a dummy window so as to have something to set the
    /// "start of new record" bit on. That way, the HDB (which simply counts those bits)
    /// will track the current record index correctly.
    Dummy {
        /// Index of record (i.e. sequence) that had no windows.
        record: usize,
    },
}

/// Generates [`SequenceWindow`]s for a single sequence according to a hash-spec obtained from HDB.
///
/// This just produces windows, and doesn't concern itself with dummy windows, or serialization
/// details like hash tags. The [`size_hint`](Self::size_hint) will be exact but operates in
/// vaguely linear-time relative to the length of the DNA. This can be constructed via
/// [`SequenceWindows::from_dna`].
#[derive(Clone)]
pub struct SequenceWindows {
    sequence: Arc<[NucleotideAmbiguous]>,
    hash_spec: ProcessedHashSpec,
    // HTD index of current_run (or which HTD will be used to build current_run if it's None)
    current_htd: u8,
    current_run: Option<WindowRun>,
}

/// Window and metadata from a single DNA sequence
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequenceWindow {
    /// Index (in hash spec HTD vector) of Hash-Type Descriptor that specified this window.
    /// This allows determining if a window e.g. contains DNA or amino acids.
    pub htd_index: u8,
    /// The range of indices in the original DNA that this window was derived from. Some caveats:
    /// * The length of [`range`](Self::range) may differ from the length of [`data`](Self::data)
    ///   when the window contains amino acids.
    /// * [`range`](Self::range) is not guaranteed to uniformly increment starting positions at a
    ///   steady rate if the DNA sequence is ambiguous. Disambiguation may result in multiple
    ///   windows with the same [`htd_index`](Self::htd_index) and [`range`](Self::range). Severe
    ///   ambiguity may result in sudden jumps/gaps in [`range`](Self::range) between windows.
    pub range: std::ops::Range<usize>,
    /// The actual window data used to produce hashes. This has been disambiguated, and has any
    /// necessary transformations applied to it, such as CECH, RC, NCBI1 DNA-to-AA mapping, etc,
    /// according to the [`htd_index`](Self::htd_index)th HTD.
    pub data: String,
}

#[derive(Clone)]
enum WindowRun {
    Dna(DnaWindows),
    Aa(AaWindows),
}

/// Internal pre-processed [`HashSpec`]
///
/// This has two goals:
/// * Do all necessary conversions/checks ahead of time so window iterators can eventually use
///   this to infallibly spawn new runs while in-progress, rather than spawning them up-front.
/// * Be cheaply cloneable, so window iterators can hold a copy of this without being expensive
///   to clone.
#[derive(Clone)]
struct ProcessedHashSpec {
    max_expansions_per_window: NonZeroUsize,
    /// Pairs of `(window len, run direction)`
    htdv: Arc<[(NonZeroUsize, Option<self::aa::Direction>)]>,
}

impl Windows {
    pub fn from_dna<D, I, N>(dna: D, spec: &HashSpec) -> Result<Self, WindowsError>
    where
        D: IntoIterator<IntoIter = I>,
        I: Iterator<Item = N>,
        N: ToNucleotideLike,
    {
        Ok(Windows {
            order_windows: OrderWindows::from_sequences([dna.into_iter()], spec)?,
            is_at_start: true,
        })
    }
}

impl Iterator for Windows {
    type Item = (HashTag, String);

    fn next(&mut self) -> Option<Self::Item> {
        let is_at_start = std::mem::take(&mut self.is_at_start);
        self.order_windows.next().map(|window| match window {
            OrderWindow::Real {
                htd_index,
                range,
                data,
                ..
            } => (HashTag::new(is_at_start, htd_index, range.start), data),
            OrderWindow::Dummy { .. } => (HashTag::dummy(), String::new()),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.order_windows.size_hint()
    }
}

impl OrderWindows {
    /// Build [`OrderWindows`] from DNA sequences and hash spec (obtained from HDB).
    pub fn from_sequences<R, D>(records: R, spec: &HashSpec) -> Result<Self, WindowsError>
    where
        R: IntoIterator<Item = D>,
        D: IntoIterator<Item: ToNucleotideLike>,
    {
        let records = records
            .into_iter()
            .map(|dna| {
                // synthclient doesn't want to specify whether nucleotides are ambiguous...
                // This is an easy, stupid way to convert everything to Vec<NucleotideAmbiguous>
                // so it can work with DnaWindows.
                dna.into_iter()
                    .map(|nuc| nuc.to_nucleotide_like().to_ascii().try_into().unwrap())
                    .collect()
            })
            .collect();
        Ok(Self {
            records,
            current_record: 0,
            hash_spec: spec.try_into()?,
            sequence_windows: None,
        })
    }

    fn remaining_sequence_iters(&self) -> impl Iterator<Item = SequenceWindows> + use<'_> {
        let indices = self.current_record + usize::from(self.sequence_windows.is_some())..;
        self.records[indices]
            .iter()
            .map(|sequence| SequenceWindows::from_arced(sequence.clone(), self.hash_spec.clone()))
    }

    fn remaining_len(&self) -> Option<usize> {
        let mut len: usize = 0;
        if let Some(windows) = &self.sequence_windows {
            // If `windows` were empty, `.next()` would have already yielded a dummy element
            // so no need to take that into account
            len = len.checked_add(windows.size_hint().1?)?;
        }
        for run in self.remaining_sequence_iters() {
            let run_len = run.size_hint().1?.max(1);
            len = len.checked_add(run_len)?;
        }
        Some(len)
    }
}

impl Iterator for OrderWindows {
    type Item = OrderWindow;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(sequence_windows) = &mut self.sequence_windows {
            if let Some(window) = sequence_windows.next() {
                return Some(window.with_record(self.current_record));
            }
            self.sequence_windows = None;
            self.current_record = (self.current_record + 1).min(self.records.len());
        }
        let seq_wins = self.remaining_sequence_iters().next()?;
        let seq_wins = self.sequence_windows.insert(seq_wins);
        if let Some(window) = seq_wins.next() {
            Some(window.with_record(self.current_record))
        } else {
            Some(OrderWindow::Dummy {
                record: self.current_record,
            })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining_len();
        (len.unwrap_or(usize::MAX), len)
    }
}

impl SequenceWindows {
    /// Build [`SequenceWindows`] from DNA sequence and hash spec (obtained from HDB).
    pub fn from_dna<D>(dna: D, spec: &HashSpec) -> Result<Self, WindowsError>
    where
        D: IntoIterator<Item: ToNucleotideLike>,
    {
        // synthclient doesn't want to specify whether nucleotides are ambiguous...
        // This is an easy, stupid way to convert everything to Vec<NucleotideAmbiguous>
        // so it can work with DnaWindows.
        let sequence = dna
            .into_iter()
            .map(|nuc| nuc.to_nucleotide_like().to_ascii().try_into().unwrap())
            .collect();
        Ok(Self {
            sequence,
            hash_spec: spec.try_into()?,
            current_htd: 0,
            current_run: None,
        })
    }

    fn from_arced(sequence: Arc<[NucleotideAmbiguous]>, hash_spec: ProcessedHashSpec) -> Self {
        Self {
            sequence,
            hash_spec,
            current_htd: 0,
            current_run: None,
        }
    }

    fn remaining_runs(&self) -> impl Iterator<Item = WindowRun> + use<'_> {
        let start = usize::from(self.current_htd) + usize::from(self.current_run.is_some());
        self.hash_spec.htdv[start..]
            .iter()
            .map(|(window_len, aa_dir)| match aa_dir {
                Some(dir) => WindowRun::Aa(AaWindows::new(
                    self.sequence.clone(),
                    *window_len,
                    Some(self.hash_spec.max_expansions_per_window),
                    *dir,
                )),
                None => WindowRun::Dna(DnaWindows::new(
                    self.sequence.clone(),
                    *window_len,
                    Some(self.hash_spec.max_expansions_per_window),
                )),
            })
    }
}

// Avoiding flatten in order to keep size_hints accurate.
impl Iterator for SequenceWindows {
    type Item = SequenceWindow;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let run = match &mut self.current_run {
                Some(run) => run,
                None => {
                    let run = self.remaining_runs().next()?;
                    self.current_run.insert(run)
                }
            };
            if let Some((range, data)) = run.next() {
                return Some(SequenceWindow {
                    htd_index: self.current_htd,
                    range,
                    data,
                });
            }
            self.current_htd += 1;
            self.current_run = None;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let first_len = self.current_run.iter().map(|run| run.size_hint().1);
        let other_lens = self.remaining_runs().map(|run| run.size_hint().1);
        let mut lens = first_len.chain(other_lens);
        let len = lens.try_fold(0usize, |total, l| total.checked_add(l?));
        (len.unwrap_or(usize::MAX), len)
    }
}

impl SequenceWindow {
    fn with_record(self, record: usize) -> OrderWindow {
        OrderWindow::Real {
            record,
            htd_index: self.htd_index,
            range: self.range,
            data: self.data,
        }
    }
}

impl Iterator for WindowRun {
    type Item = (std::ops::Range<usize>, String);

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: don't allocate new strings every time
        fn dna_to_string(dna: DnaWindow) -> String {
            dna.iter().map(|&nuc| char::from(nuc)).collect()
        }

        match self {
            Self::Dna(iter) => iter.next().map(|(i, dna)| (i, dna_to_string(dna))),
            Self::Aa(iter) => iter.next().map(|(i, aas)| (i, aas.as_ref().to_owned())),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Dna(iter) => iter.size_hint(),
            Self::Aa(iter) => iter.size_hint(),
        }
    }
}

impl TryFrom<&HashSpec> for ProcessedHashSpec {
    type Error = WindowsError;

    fn try_from(hash_spec: &HashSpec) -> Result<Self, Self::Error> {
        if hash_spec.htdv.len() > usize::from(u8::MAX) {
            return Err(WindowsError::TooManyHtds);
        }
        let htdv: Result<_, _> = hash_spec
            .htdv
            .iter()
            .map(|htd| {
                let window_len = NonZeroUsize::try_from(htd.width)
                    .map_err(|_| WindowsError::ZeroWindowLength(htd.clone()))?;

                if htd.skip_type != HashSkipType::Shingled {
                    return Err(WindowsError::NonShingledHtd(htd.clone()));
                }

                match (htd.hash_type, htd.direction.try_into()) {
                    (HashType::Dna, Err(HashDirection::CECH)) => Ok((window_len, None)),
                    (HashType::Aa, Ok(direction)) => Ok((window_len, Some(direction))),
                    _ => Err(WindowsError::UnsupportedHtd(htd.clone())),
                }
            })
            .collect();
        Ok(Self {
            max_expansions_per_window: hash_spec.max_expansions_per_window,
            htdv: htdv?,
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use quickcheck::{Arbitrary, Gen, TestResult, quickcheck};

    use quickdna::{BaseSequence, DnaSequenceStrict, Nucleotide};
    use shared_types::hash::{HashDirection, HashType, HashTypeDescriptor};
    use shared_types::{WINDOW_LENGTH_AA, WINDOW_LENGTH_DNA_NORMAL, WINDOW_LENGTH_DNA_RUNT};

    use super::*;

    #[test]
    fn sanity_check_windows() {
        // 64 nucleotides long
        let dna: DnaSequenceStrict =
            "AAGCAAGAGAGATTTTCGCTGCTGCGCGGCAGAGAGCGCGGCCTGAGTTACTATGGCTTGTCTA"
                .parse()
                .unwrap();

        let spec = HashSpec::unambiguous(vec![
            HashTypeDescriptor::dna_normal_cech(),
            HashTypeDescriptor::dna_runt_cech(),
            HashTypeDescriptor::aa_fw(),
            HashTypeDescriptor::aa_rc(),
        ]);
        let windows: HashSet<_> = Windows::from_dna(dna.iter(), &spec)
            .unwrap()
            .map(|(i, x)| (i.index_in_record(), x))
            .collect();

        fn first_n(seq: &str, n: usize) -> String {
            seq[..n].to_owned()
        }
        fn last_n(seq: &str, n: usize) -> String {
            seq[seq.len().saturating_sub(n)..].to_owned()
        }

        // First windows
        assert!(windows.contains(&(0, "AATCAATATATAGGGGCTCGTCGTCTCTTCATATATCTCTTC".to_owned()))); // hog
        assert!(windows.contains(&(0, "AATCAATATATAGGGGCTCGTCGTCTCTTC".to_owned()))); // runt
        assert!(windows.contains(&(0, first_n("KQERFSLLRGRERGLSYYGL", WINDOW_LENGTH_AA)))); // aa
        assert!(windows.contains(&(0, last_n("QAIVTQAALSAAQQRKSLLL", WINDOW_LENGTH_AA)))); // aa (rc)

        // Last windows
        assert!(windows.contains(&(22, "ATCTCTTCGTGTGTCTCTTCCATGTAAGCAGATTCAATACAG".to_owned()))); // hog
        assert!(windows.contains(&(34, "ATCTCTTCCGTATGGACGAGTTCGGTGCGA".to_owned()))); // runt
        assert!(windows.contains(&(4, first_n("KRDFRCCAAESAA*VTMACL", WINDOW_LENGTH_AA)))); // aa
        assert!(windows.contains(&(4, last_n("*TSHSNSGRALCRAAAKISL", WINDOW_LENGTH_AA)))); // aa (rc)

        let spec = HashSpec::unambiguous(vec![
            HashTypeDescriptor::dna_normal_cech(),
            HashTypeDescriptor::dna_runt_cech(),
        ]);

        let windows: HashSet<_> = Windows::from_dna(dna.iter(), &spec)
            .unwrap()
            .map(|(i, x)| (i.index_in_record(), x))
            .collect();

        // First windows
        assert!(windows.contains(&(0, "AATCAATATATAGGGGCTCGTCGTCTCTTCATATATCTCTTC".to_owned()))); // hog
        assert!(windows.contains(&(0, "AATCAATATATAGGGGCTCGTCGTCTCTTC".to_owned()))); // runt
        assert!(!windows.contains(&(0, first_n("KQERFSLLRGRERGLSYYGL", WINDOW_LENGTH_AA)))); // aa
        assert!(!windows.contains(&(0, last_n("QAIVTQAALSAAQQRKSLLL", WINDOW_LENGTH_AA)))); // aa (rc)

        // Last windows
        assert!(windows.contains(&(22, "ATCTCTTCGTGTGTCTCTTCCATGTAAGCAGATTCAATACAG".to_owned()))); // hog
        assert!(windows.contains(&(34, "ATCTCTTCCGTATGGACGAGTTCGGTGCGA".to_owned()))); // runt
        assert!(!windows.contains(&(4, first_n("KRDFRCCAAESAA*VTMACL", WINDOW_LENGTH_AA)))); // aa
        assert!(!windows.contains(&(4, last_n("*TSHSNSGRALCRAAAKISL", WINDOW_LENGTH_AA)))); // aa (rc)

        let spec = HashSpec::unambiguous(vec![
            HashTypeDescriptor::dna_normal_cech(),
            HashTypeDescriptor::aa_fw(),
            HashTypeDescriptor::aa_rc(),
        ]);

        let windows: HashSet<_> = Windows::from_dna(dna.iter(), &spec)
            .unwrap()
            .map(|(i, x)| (i.index_in_record(), x))
            .collect();

        // First windows
        assert!(windows.contains(&(0, "AATCAATATATAGGGGCTCGTCGTCTCTTCATATATCTCTTC".to_owned()))); // hog
        assert!(!windows.contains(&(0, "AATCAATATATAGGGGCTCGTCGTCTCTTC".to_owned()))); // runt
        assert!(windows.contains(&(0, first_n("KQERFSLLRGRERGLSYYGL", WINDOW_LENGTH_AA)))); // aa
        assert!(windows.contains(&(0, last_n("QAIVTQAALSAAQQRKSLLL", WINDOW_LENGTH_AA)))); // aa (rc)

        // Last windows
        assert!(windows.contains(&(22, "ATCTCTTCGTGTGTCTCTTCCATGTAAGCAGATTCAATACAG".to_owned()))); // hog
        assert!(!windows.contains(&(34, "ATCTCTTCCGTATGGACGAGTTCGGTGCGA".to_owned()))); // runt
        assert!(windows.contains(&(4, first_n("KRDFRCCAAESAA*VTMACL", WINDOW_LENGTH_AA)))); // aa
        assert!(windows.contains(&(4, last_n("*TSHSNSGRALCRAAAKISL", WINDOW_LENGTH_AA)))); // aa (rc)
    }

    #[test]
    fn sanity_check_lengths() {
        // 64 nucleotides long
        let dna: DnaSequenceStrict =
            "AAGCAAGAGAGATTTTCGCTGCTGCGCGGCAGAGAGCGCGGCCTGAGTTACTATGGCTTGTCTA"
                .parse()
                .unwrap();

        let spec = HashSpec::unambiguous(vec![]);
        let windows = Windows::from_dna(dna.iter(), &spec).unwrap();
        // Makes a dummy window:
        assert_eq!(windows.size_hint(), (1, Some(1)));

        let spec = HashSpec::unambiguous(vec![HashTypeDescriptor::dna_normal_cech()]);
        let windows = Windows::from_dna(dna.iter(), &spec).unwrap();
        let expected_hogs_len = dna.len() - WINDOW_LENGTH_DNA_NORMAL + 1;
        assert_eq!(
            windows.size_hint(),
            (expected_hogs_len, Some(expected_hogs_len))
        );

        let spec = HashSpec::unambiguous(vec![HashTypeDescriptor::dna_runt_cech()]);
        let windows = Windows::from_dna(dna.iter(), &spec).unwrap();
        let expected_runts_len = dna.len() - WINDOW_LENGTH_DNA_RUNT + 1;
        assert_eq!(
            windows.size_hint(),
            (expected_runts_len, Some(expected_runts_len))
        );

        let spec = HashSpec::unambiguous(vec![
            HashTypeDescriptor::aa_fw(),
            HashTypeDescriptor::aa_rc(),
        ]);
        let windows = Windows::from_dna(dna.iter(), &spec).unwrap();

        let expected_aas_len = 2 * (dna.len() - 3 * WINDOW_LENGTH_AA + 1);
        assert_eq!(
            windows.size_hint(),
            (expected_aas_len, Some(expected_aas_len))
        );

        let spec = HashSpec::unambiguous(vec![
            HashTypeDescriptor::dna_normal_cech(),
            HashTypeDescriptor::dna_runt_cech(),
            HashTypeDescriptor::aa_fw(),
            HashTypeDescriptor::aa_rc(),
        ]);
        let mut windows = Windows::from_dna(dna.iter(), &spec).unwrap();

        let total = expected_hogs_len + expected_runts_len + expected_aas_len;

        // Check that the size hints remain correct as we consume the iterator:
        for remaining in (1..=total).rev() {
            assert_eq!(windows.size_hint(), (remaining, Some(remaining)));
            assert!(windows.next().is_some());
        }
        assert_eq!(windows.size_hint(), (0, Some(0)));
        assert!(windows.next().is_none());
    }

    #[test]
    fn check_bad_htdv() {
        // 64 nucleotides long
        let dna: DnaSequenceStrict =
            "AAGCAAGAGAGATTTTCGCTGCTGCGCGGCAGAGAGCGCGGCCTGAGTTACTATGGCTTGTCTA"
                .parse()
                .unwrap();

        let zero_htd = HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: 0,
            direction: HashDirection::CECH,
            skip_type: HashSkipType::Shingled,
        };
        assert_eq!(
            Windows::from_dna(dna.iter(), &HashSpec::unambiguous(vec![zero_htd.clone()])).err(),
            Some(WindowsError::ZeroWindowLength(zero_htd))
        );

        let tiled_htd = HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: 42,
            direction: HashDirection::CECH,
            skip_type: HashSkipType::Tiled,
        };
        assert_eq!(
            Windows::from_dna(dna.iter(), &HashSpec::unambiguous(vec![tiled_htd.clone()])).err(),
            Some(WindowsError::NonShingledHtd(tiled_htd))
        );

        // DNA + RC is not supported anymore, only CECH is.
        let rc_dna_htd = HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: 42,
            direction: HashDirection::RC,
            skip_type: HashSkipType::Shingled,
        };
        assert_eq!(
            Windows::from_dna(dna.iter(), &HashSpec::unambiguous(vec![rc_dna_htd.clone()])).err(),
            Some(WindowsError::UnsupportedHtd(rc_dna_htd))
        );
    }

    #[test]
    fn makes_dummy_window_if_too_short() {
        // Too short to make any windows
        let dna: DnaSequenceStrict = "AAGCAAGAGA".parse().unwrap();
        let windows = Windows::from_dna(
            dna.iter(),
            &HashSpec::unambiguous(vec![
                HashTypeDescriptor::dna_normal_cech(),
                HashTypeDescriptor::dna_runt_cech(),
                HashTypeDescriptor::aa_fw(),
            ]),
        )
        .unwrap();

        // Makes a single dummy window
        assert_eq!(windows.size_hint(), (1, Some(1)));
        let window_vec: Vec<(HashTag, String)> = windows.collect();
        let dummy = (HashTag::new(true, 0, 0), "".to_owned());
        assert_eq!(window_vec, vec![dummy]);
    }

    #[derive(Clone)]
    struct SaneTypeDescriptor(HashTypeDescriptor);

    impl Arbitrary for SaneTypeDescriptor {
        fn arbitrary(g: &mut Gen) -> Self {
            if bool::arbitrary(g) {
                Self(HashTypeDescriptor {
                    hash_type: HashType::Dna,
                    direction: HashDirection::CECH,
                    width: usize::arbitrary(g) % 60 + 1,
                    skip_type: HashSkipType::Shingled,
                })
            } else {
                Self(HashTypeDescriptor {
                    hash_type: HashType::Aa,
                    direction: if bool::arbitrary(g) {
                        HashDirection::FW
                    } else {
                        HashDirection::RC
                    },
                    width: usize::arbitrary(g) % 30 + 1,
                    skip_type: HashSkipType::Shingled,
                })
            }
        }
    }

    #[derive(Clone, Debug)]
    struct SaneHashSpec(HashSpec);

    impl Arbitrary for SaneHashSpec {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(HashSpec {
                max_expansions_per_window: NonZeroUsize::arbitrary(g),
                htdv: Vec::arbitrary(g)
                    .into_iter()
                    .map(|SaneTypeDescriptor(htd)| htd)
                    .collect(),
            })
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            let htdv = &self.0.htdv;
            let htdv: Vec<_> = htdv.iter().cloned().map(SaneTypeDescriptor).collect();
            let shrunk = (self.0.max_expansions_per_window, htdv).shrink().map(
                |(max_expansions_per_window, htdv)| {
                    let htdv = htdv.into_iter().map(|htd| htd.0).collect();
                    Self(HashSpec {
                        max_expansions_per_window,
                        htdv,
                    })
                },
            );
            Box::new(shrunk)
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct WindowLen(pub usize);

    impl WindowLen {
        pub fn for_slice<T>(&self, slice: &[T]) -> NonZeroUsize {
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
    pub(crate) struct SemiAmbiguousDna(pub Vec<NucleotideAmbiguous>);

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
    pub(crate) struct Oligo(pub Vec<NucleotideAmbiguous>);

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

    // Max length of windows iterators that will be checked by the quickcheck tests
    const MAX_ITER_LEN: usize = 10_000;

    fn order_windows_reference_implementation<R, D>(
        records: R,
        spec: &HashSpec,
    ) -> Result<Vec<OrderWindow>, WindowsError>
    where
        R: IntoIterator<Item = D>,
        D: IntoIterator<Item: ToNucleotideLike>,
    {
        let mut output = vec![];
        for (record, dna) in records.into_iter().enumerate() {
            let sequence_windows = sequence_windows_reference_implementation(dna, spec)?;
            if sequence_windows.is_empty() {
                output.push(OrderWindow::Dummy { record });
            }
            for window in sequence_windows {
                output.push(window.with_record(record));
            }
        }
        Ok(output)
    }

    fn sequence_windows_reference_implementation<D>(
        dna: D,
        spec: &HashSpec,
    ) -> Result<Vec<SequenceWindow>, WindowsError>
    where
        D: IntoIterator<Item: ToNucleotideLike>,
    {
        let sequence: Arc<[NucleotideAmbiguous]> = dna
            .into_iter()
            .map(|nuc| nuc.to_nucleotide_like().to_ascii().try_into().unwrap())
            .collect();
        let hash_spec = ProcessedHashSpec::try_from(spec)?;

        let mut output = vec![];
        for (htd_index, (window_len, aa_dir)) in hash_spec.htdv.iter().enumerate() {
            let run = match aa_dir {
                Some(dir) => WindowRun::Aa(AaWindows::new(
                    sequence.clone(),
                    *window_len,
                    Some(spec.max_expansions_per_window),
                    *dir,
                )),
                None => WindowRun::Dna(DnaWindows::new(
                    sequence.clone(),
                    *window_len,
                    Some(spec.max_expansions_per_window),
                )),
            };
            for (range, data) in run {
                output.push(SequenceWindow {
                    htd_index: htd_index as u8,
                    range,
                    data,
                })
            }
        }
        Ok(output)
    }

    fn is_iter_eq<I: Iterator>(mut iter: I, expected: Vec<I::Item>) -> bool
    where
        I::Item: Eq + std::fmt::Debug,
    {
        let expected_len = expected.len();
        for (i, item) in expected.into_iter().enumerate() {
            let remaining = expected_len - i;
            if iter.size_hint() != (remaining, Some(remaining)) || iter.next() != Some(item) {
                return false;
            }
        }
        iter.size_hint() == (0, Some(0)) && iter.next().is_none()
    }

    fn is_iter_result_eq<I: Iterator, E>(
        iter: Result<I, E>,
        expected: Result<Vec<I::Item>, E>,
    ) -> bool
    where
        I::Item: Eq + std::fmt::Debug,
        E: Eq,
    {
        match (iter, expected) {
            (Ok(iter), Ok(expected)) => is_iter_eq(iter, expected),
            (Err(err1), Err(err2)) => err1 == err2,
            _ => false,
        }
    }

    quickcheck! {
        fn unambiguous_order_windows_match_reference_implementation(
            sequences: Vec<Vec<Nucleotide>>,
            spec: SaneHashSpec
        ) -> TestResult {
            let actual = OrderWindows::from_sequences(&sequences, &spec.0);
            if let Ok(actual) = &actual
                && actual.size_hint().0 > MAX_ITER_LEN
            {
                return TestResult::discard();
            }
            let expected = order_windows_reference_implementation(&sequences, &spec.0);
            TestResult::from_bool(is_iter_result_eq(actual, expected))
        }

        fn very_ambiguous_order_windows_match_reference_implementation(
            sequences: Vec<Vec<NucleotideAmbiguous>>,
            spec: SaneHashSpec
        ) -> TestResult {
            let actual = OrderWindows::from_sequences(&sequences, &spec.0);
            if let Ok(actual) = &actual
                && actual.size_hint().0 > MAX_ITER_LEN
            {
                return TestResult::discard();
            }
            let expected = order_windows_reference_implementation(&sequences, &spec.0);
            TestResult::from_bool(is_iter_result_eq(actual, expected))
        }

        fn less_ambiguous_order_windows_match_reference_implementation(
            sequences: Vec<SemiAmbiguousDna>,
            spec: SaneHashSpec
        ) -> TestResult {
            let sequences: Vec<_> = sequences.into_iter().map(|dna| dna.0).collect();
            let actual = OrderWindows::from_sequences(&sequences, &spec.0);
            if let Ok(actual) = &actual
                && actual.size_hint().0 > MAX_ITER_LEN
            {
                return TestResult::discard();
            }
            let expected = order_windows_reference_implementation(&sequences, &spec.0);
            TestResult::from_bool(is_iter_result_eq(actual, expected))
        }

        fn oligo_order_windows_match_reference_implementation(
            sequences: Vec<Oligo>,
            spec: SaneHashSpec
        ) -> TestResult {
            let sequences: Vec<_> = sequences.into_iter().map(|dna| dna.0).collect();
            let actual = OrderWindows::from_sequences(&sequences, &spec.0);
            if let Ok(actual) = &actual
                && actual.size_hint().0 > MAX_ITER_LEN
            {
                return TestResult::discard();
            }
            let expected = order_windows_reference_implementation(&sequences, &spec.0);
            TestResult::from_bool(is_iter_result_eq(actual, expected))
        }

        fn unambiguous_sequence_windows_match_reference_implementation(
            dna: Vec<Nucleotide>,
            spec: SaneHashSpec
        ) -> TestResult {
            let actual = SequenceWindows::from_dna(&dna, &spec.0);
            if let Ok(actual) = &actual
                && actual.size_hint().0 > MAX_ITER_LEN
            {
                return TestResult::discard();
            }
            let expected = sequence_windows_reference_implementation(&dna, &spec.0);
            TestResult::from_bool(is_iter_result_eq(actual, expected))
        }

        fn very_ambiguous_sequence_windows_match_reference_implementation(
            dna: Vec<NucleotideAmbiguous>,
            spec: SaneHashSpec
        ) -> TestResult {
            let actual = SequenceWindows::from_dna(&dna, &spec.0);
            if let Ok(actual) = &actual
                && actual.size_hint().0 > MAX_ITER_LEN
            {
                return TestResult::discard();
            }
            let expected = sequence_windows_reference_implementation(&dna, &spec.0);
            TestResult::from_bool(is_iter_result_eq(actual, expected))
        }

        fn less_ambiguous_sequence_windows_match_reference_implementation(
            dna: SemiAmbiguousDna,
            spec: SaneHashSpec
        ) -> TestResult {
            let actual = SequenceWindows::from_dna(&dna.0, &spec.0);
            if let Ok(actual) = &actual
                && actual.size_hint().0 > MAX_ITER_LEN
            {
                return TestResult::discard();
            }
            let expected = sequence_windows_reference_implementation(&dna.0, &spec.0);
            TestResult::from_bool(is_iter_result_eq(actual, expected))
        }

        fn oligo_sequence_windows_match_reference_implementation(
            dna: Oligo,
            spec: SaneHashSpec
        ) -> TestResult {
            let actual = SequenceWindows::from_dna(&dna.0, &spec.0);
            if let Ok(actual) = &actual
                && actual.size_hint().0 > MAX_ITER_LEN
            {
                return TestResult::discard();
            }
            let expected = sequence_windows_reference_implementation(&dna.0, &spec.0);
            TestResult::from_bool(is_iter_result_eq(actual, expected))
        }
    }
}
