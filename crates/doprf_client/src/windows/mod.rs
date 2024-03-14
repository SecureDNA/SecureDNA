// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers related to generating all windows of a strand of DNA

use std::num::NonZeroUsize;

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
    runs: Vec<WindowRun>,
    current_htd: u8,
    is_at_start: bool,
}

#[derive(Clone)]
enum WindowRun {
    Dna(DnaWindows),
    Aa(AaWindows),
}

impl Windows {
    pub fn from_dna<D, I, N>(dna: D, spec: &HashSpec) -> Result<Self, WindowsError>
    where
        D: IntoIterator<IntoIter = I>,
        I: Iterator<Item = N>,
        N: ToNucleotideLike,
    {
        // synthclient doesn't want to specify whether nucleotides are ambiguous...
        // This is an easy, stupid way to convert everything to Vec<NucleotideAmbiguous>
        // so it can work with DnaWindows.
        let dna: Vec<NucleotideAmbiguous> = dna
            .into_iter()
            .map(|nuc| nuc.to_nucleotide_like().to_ascii().try_into().unwrap())
            .collect();

        if spec.htdv.len() > u8::MAX as usize {
            return Err(WindowsError::TooManyHtds);
        }

        let runs: Result<Vec<_>, _> = spec
            .htdv
            .iter()
            .rev() // the Iterator impl starts at the end and pops iters off
            .map(|htd| {
                let window_len: NonZeroUsize = htd
                    .width
                    .try_into()
                    .map_err(|_| WindowsError::ZeroWindowLength(htd.clone()))?;

                if htd.skip_type != HashSkipType::Shingled {
                    return Err(WindowsError::NonShingledHtd(htd.clone()));
                }

                match (htd.hash_type, htd.direction.try_into()) {
                    (HashType::Dna, Err(HashDirection::CECH)) => {
                        let windows = DnaWindows::new(
                            dna.clone(),
                            window_len,
                            Some(spec.max_expansions_per_window),
                        );
                        Ok(WindowRun::Dna(windows))
                    }
                    (HashType::Aa, Ok(direction)) => {
                        let windows = AaWindows::new(
                            dna.clone().into(),
                            window_len,
                            Some(spec.max_expansions_per_window),
                            direction,
                        );
                        Ok(WindowRun::Aa(windows))
                    }
                    _ => Err(WindowsError::UnsupportedHtd(htd.clone())),
                }
            })
            .collect();

        Ok(Windows {
            runs: runs?,
            current_htd: 0,
            is_at_start: true,
        })
    }
}

// Avoiding flatten in order to keep size_hints accurate.
impl Iterator for Windows {
    type Item = (HashTag, String);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(run) = self.runs.last_mut() {
            if let Some((indexes, window)) = run.next() {
                let hash_tag = HashTag::new(self.is_at_start, self.current_htd, indexes.start);
                self.is_at_start = false;
                return Some((hash_tag, window));
            }
            self.runs.pop();
            self.current_htd += 1;
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut min: usize = 0;
        let mut max: Option<usize> = Some(0);
        for run in &self.runs {
            let (run_min, run_max) = run.size_hint();
            min = min.saturating_add(run_min);
            max = max.and_then(|m| m.checked_add(run_max?));
        }
        (min, max)
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

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use quickdna::{BaseSequence, DnaSequenceStrict};
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

        // First windows
        assert!(windows.contains(&(0, "AATCAATATATAGGGGCTCGTCGTCTCTTCATATATCTCTTC".to_owned()))); // hog
        assert!(windows.contains(&(0, "AATCAATATATAGGGGCTCGTCGTCTCTTC".to_owned()))); // runt
        assert!(windows.contains(&(0, "KQERFSLLRGRERGLSYYGL".to_owned()))); // aa
        assert!(windows.contains(&(0, "QAIVTQAALSAAQQRKSLLL".to_owned()))); // aa (rc)

        // Last windows
        assert!(windows.contains(&(22, "ATCTCTTCGTGTGTCTCTTCCATGTAAGCAGATTCAATACAG".to_owned()))); // hog
        assert!(windows.contains(&(34, "ATCTCTTCCGTATGGACGAGTTCGGTGCGA".to_owned()))); // runt
        assert!(windows.contains(&(4, "KRDFRCCAAESAA*VTMACL".to_owned()))); // aa
        assert!(windows.contains(&(4, "*TSHSNSGRALCRAAAKISL".to_owned()))); // aa (rc)

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
        assert!(!windows.contains(&(0, "KQERFSLLRGRERGLSYYGL".to_owned()))); // aa
        assert!(!windows.contains(&(0, "QAIVTQAALSAAQQRKSLLL".to_owned()))); // aa (rc)

        // Last windows
        assert!(windows.contains(&(22, "ATCTCTTCGTGTGTCTCTTCCATGTAAGCAGATTCAATACAG".to_owned()))); // hog
        assert!(windows.contains(&(34, "ATCTCTTCCGTATGGACGAGTTCGGTGCGA".to_owned()))); // runt
        assert!(!windows.contains(&(4, "KRDFRCCAAESAA*VTMACL".to_owned()))); // aa
        assert!(!windows.contains(&(4, "*TSHSNSGRALCRAAAKISL".to_owned()))); // aa (rc)

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
        assert!(windows.contains(&(0, "KQERFSLLRGRERGLSYYGL".to_owned()))); // aa
        assert!(windows.contains(&(0, "QAIVTQAALSAAQQRKSLLL".to_owned()))); // aa (rc)

        // Last windows
        assert!(windows.contains(&(22, "ATCTCTTCGTGTGTCTCTTCCATGTAAGCAGATTCAATACAG".to_owned()))); // hog
        assert!(!windows.contains(&(34, "ATCTCTTCCGTATGGACGAGTTCGGTGCGA".to_owned()))); // runt
        assert!(windows.contains(&(4, "KRDFRCCAAESAA*VTMACL".to_owned()))); // aa
        assert!(windows.contains(&(4, "*TSHSNSGRALCRAAAKISL".to_owned()))); // aa (rc)
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
        assert_eq!(windows.size_hint(), (0, Some(0)));

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
        let windows = Windows::from_dna(dna.iter(), &spec).unwrap();

        let expected_len = expected_hogs_len + expected_runts_len + expected_aas_len;
        assert_eq!(windows.size_hint(), (expected_len, Some(expected_len)));
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
}
