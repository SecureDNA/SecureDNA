// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared types relating to hashes, hashing, and DNA/AA windows.

use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use thiserror::Error;

/// The size of a normal ("hog") DNA window, in nucleotides.
pub const WINDOW_LENGTH_DNA_NORMAL: usize = 42;

/// The size of a short "runt" DNA window, in nucleotides.
pub const WINDOW_LENGTH_DNA_RUNT: usize = 30;

/// The size of an amino acid window, in amino acids.
pub const WINDOW_LENGTH_AA: usize = 20;

/// Describes how the windows were treated during hashing: DNA, or amino acids
/// in some reading frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashType {
    /// These hashes are from DNA windows.
    #[serde(rename = "dna")]
    Dna,
    /// These hashes are from amino acid windows with all reading frames interleaved.
    #[serde(rename = "aa")]
    Aa,
    /// These hashes are from amino acid windows in reading frame 0.
    #[serde(rename = "aa0")]
    Aa0,
    /// These hashes are from amino acid windows in reading frame 1.
    #[serde(rename = "aa1")]
    Aa1,
    /// These hashes are from amino acid windows in reading frame 2.
    #[serde(rename = "aa2")]
    Aa2,
}

impl HashType {
    /// The increment between successive shingled hashes in nucleotides. This is
    /// the length in nucleotides between successive starting positions of the windows.
    pub fn increment(&self) -> usize {
        match self {
            Self::Dna | Self::Aa => 1,
            Self::Aa0 | Self::Aa1 | Self::Aa2 => 3,
        }
    }

    /// The offset into a sequence of any first hash of this type, or in other
    /// words, the reading frame number of this hash type.
    pub fn sequence_offset(&self) -> usize {
        match self {
            Self::Dna | Self::Aa => 0,
            Self::Aa0 => 0,
            Self::Aa1 => 1,
            Self::Aa2 => 2,
        }
    }

    /// The size in nucleotides of a single "letter" of a window type:
    ///  1 for DNA, 3 for amino acids
    pub fn letter_width_bp(&self) -> usize {
        match self {
            Self::Dna => 1,
            Self::Aa | Self::Aa0 | Self::Aa1 | Self::Aa2 => 3,
        }
    }
}

/// Describes which direction windows were read in to create the hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashDirection {
    /// These hashes were made by reading windows in the forward direction.
    FW,
    /// These hashes were made by reading the reverse complement of each window.
    RC,
    /// These hashes were made by permuting the bases of a window, and possibly
    /// reversing the window ("combinatorial equivalence class hashing").
    CECH,
}

/// Describes how the sequence was skipped through to turn it into windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashSkipType {
    /// The windows were made by shingling the sequence: "ABCDE", then "BCDEF",
    /// then "CDEFG"...
    #[serde(rename = "shingled")]
    Shingled,
    /// The windows were made by tiling the sequence: "ABCDE", then "FGHIJ",
    /// then "KLMNO"...
    #[serde(rename = "tiled")]
    Tiled,
}

/// Describes a way to make windows/hashes from a sequence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HashTypeDescriptor {
    /// Are these DNA or AA windows? In which reading frame?
    #[serde(rename = "type")]
    pub hash_type: HashType,
    /// Width of each window (in "letters", not in bp!)
    ///
    /// - For DNA windows, this is 42 (hog) or 30 (runt).
    /// - For amino acid hashes/windows, this is 20, not 60.
    pub width: usize,
    /// Direction windows are read in.
    pub direction: HashDirection,
    /// How the sequence was skipped through to turn it into windows.
    #[serde(rename = "skiptype")]
    pub skip_type: HashSkipType,
}

impl HashTypeDescriptor {
    /// A HTD for normal-size ("hog"), shingled DNA windows in the forward
    /// direction.
    pub fn dna_normal_fw() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: WINDOW_LENGTH_DNA_NORMAL,
            direction: HashDirection::FW,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for normal-size ("hog"), shingled DNA windows in the reverse
    /// complement direction.
    pub fn dna_normal_rc() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: WINDOW_LENGTH_DNA_NORMAL,
            direction: HashDirection::RC,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for normal-size ("hog"), shingled DNA windows using CECH
    /// (combinatorial equivalence class hashing).
    pub fn dna_normal_cech() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: WINDOW_LENGTH_DNA_NORMAL,
            direction: HashDirection::CECH,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for shingled DNA runts in the forward direction.
    pub fn dna_runt_fw() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: WINDOW_LENGTH_DNA_RUNT,
            direction: HashDirection::FW,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for DNA runts, shingled DNA windows using CECH
    /// (combinatorial equivalence class hashing).
    pub fn dna_runt_cech() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: WINDOW_LENGTH_DNA_RUNT,
            direction: HashDirection::CECH,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for tiled DNA runts in the forward direction.
    pub fn dna_runt_fw_tiled() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: WINDOW_LENGTH_DNA_RUNT,
            direction: HashDirection::FW,
            skip_type: HashSkipType::Tiled,
        }
    }

    /// A HTD for shingled DNA runts in the reverse complement direction.
    pub fn dna_runt_rc() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Dna,
            width: WINDOW_LENGTH_DNA_RUNT,
            direction: HashDirection::RC,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for shingled amino acids, forward, with interleaved reading frames.
    pub fn aa_fw() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::FW,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for shingled amino acids, forward, in reading frame 0.
    pub fn aa0_fw() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa0,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::FW,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for tiled amino acids, forward, in reading frame 0.
    pub fn aa0_fw_tiled() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa0,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::FW,
            skip_type: HashSkipType::Tiled,
        }
    }

    /// A HTD for shingled amino acids, forward, in reading frame 1.
    pub fn aa1_fw() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa1,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::FW,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for shingled amino acids, forward, in reading frame 2.
    pub fn aa2_fw() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa2,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::FW,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for shingled amino acids, reverse complement, with interleaved reading frames.
    pub fn aa_rc() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::RC,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for shingled amino acids, reverse complement, in reading frame 0.
    pub fn aa0_rc() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa0,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::RC,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for shingled amino acids, reverse complement, in reading frame 1.
    pub fn aa1_rc() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa1,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::RC,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// A HTD for shingled amino acids, reverse complement, in reading frame 2.
    pub fn aa2_rc() -> Self {
        HashTypeDescriptor {
            hash_type: HashType::Aa2,
            width: WINDOW_LENGTH_AA,
            direction: HashDirection::RC,
            skip_type: HashSkipType::Shingled,
        }
    }

    /// Return the width of each window *in nucleotides*, not in letters.
    ///
    /// - For DNA windows, this is 42 (hog) or 30 (runt).
    /// - For amino acid hashes/windows, this is 60, not 20.
    pub fn width_bp(&self) -> usize {
        self.width * self.hash_type.letter_width_bp()
    }

    /// Given an index into a list of hashes matching this hash type descriptor,
    /// return the starting index into the original sequence (counting
    /// nucleotides) of the window that originates that hash.
    ///
    /// For example, if the HTD is "shingled amino acids in reading frame 1" and
    /// hash_index is 4, the result is 1 + 3*4 = 13, because `hashes[4]` was made
    /// by hashing the window `seq[13..73]`.
    pub fn sequence_index(&self, hash_index: usize) -> usize {
        self.hash_type.sequence_offset() + hash_index * self.increment()
    }

    /// The increase in sequence_index (counting nucleotides) between successive
    /// hashes:
    ///
    /// * 1 for shingled DNA
    /// * 3 for shingled AAs
    /// * 42 for normal tiled DNA
    /// * 30 for tiled DNA runts
    /// * 3*20 = 60 for tiled AAs
    pub fn increment(&self) -> usize {
        match self.skip_type {
            HashSkipType::Shingled => self.hash_type.increment(),
            HashSkipType::Tiled => self.width_bp(),
        }
    }
}

/// A specification of which hashes to make and how to make them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HashSpec {
    pub max_expansions_per_window: NonZeroUsize,
    pub htdv: Vec<HashTypeDescriptor>,
}

#[derive(Debug, Error)]
pub enum HashSpecValidationError {
    #[error("too many hash types (max {})", HashSpec::MAX_HASH_TYPES)]
    TooManyHashTypes,
}

impl HashSpec {
    const MAX_HASH_TYPES: usize = 15;

    /// Create a HashSpec that does not expand ambiguities, i.e.
    /// `max_expansions_per_window` is set to 1.
    pub fn unambiguous(htdv: Vec<HashTypeDescriptor>) -> Self {
        Self {
            max_expansions_per_window: NonZeroUsize::MIN,
            htdv,
        }
    }

    /// Create a HashSpec that only covers normal-size CECH DNA windows and does
    /// not expand ambiguities.
    pub fn dna_normal_cech() -> Self {
        Self::unambiguous(vec![HashTypeDescriptor::dna_normal_cech()])
    }

    /// Create a HashSpec from a legacy `include_runts` flag.
    ///
    /// * If `true`, the specification says to never expand ambiguities, and to include hogs, runts, and AAs.
    /// * If `false`, runts are excluded.
    ///
    /// TODO: instead of ever calling this function, get an actual HTDV from the HDB.
    pub fn from_include_runts(include_runts: bool) -> Self {
        HashSpec {
            max_expansions_per_window: NonZeroUsize::MIN,
            htdv: if include_runts {
                vec![
                    HashTypeDescriptor::dna_normal_cech(),
                    HashTypeDescriptor::dna_runt_cech(),
                    HashTypeDescriptor::aa_fw(),
                    HashTypeDescriptor::aa_rc(),
                ]
            } else {
                vec![
                    HashTypeDescriptor::dna_normal_cech(),
                    HashTypeDescriptor::aa_fw(),
                    HashTypeDescriptor::aa_rc(),
                ]
            },
        }
    }

    pub fn validate(&self) -> Result<(), HashSpecValidationError> {
        if self.htdv.len() > Self::MAX_HASH_TYPES {
            return Err(HashSpecValidationError::TooManyHashTypes);
        }
        Ok(())
    }

    pub fn min_width_bp(&self) -> Option<usize> {
        self.htdv.iter().map(|h| h.width_bp()).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_interleaved_aa_has_correct_window_width_and_increment() {
        assert_eq!(HashTypeDescriptor::aa_fw().width_bp(), 3 * WINDOW_LENGTH_AA);
        assert_eq!(HashTypeDescriptor::aa_rc().width_bp(), 3 * WINDOW_LENGTH_AA);
        assert_eq!(HashTypeDescriptor::aa_fw().increment(), 1);
        assert_eq!(HashTypeDescriptor::aa_rc().increment(), 1);
    }
}
