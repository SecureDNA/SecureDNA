// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Serialize, Deserialize,
)]
#[repr(u8)]
/// The provenance of a database entry.
/// This enum must fit into 3 bits.
pub enum Provenance {
    DnaNormal = 0,
    AAWildType = 1,
    AASingleReplacement = 2,
    AADoubleReplacement = 3,
    AASampled = 4,
    DnaRunt = 5,
}

impl Provenance {
    /// Whether this provenance is for a DNA hazard or not.
    pub fn is_dna(&self) -> bool {
        match self {
            Self::DnaNormal | Self::DnaRunt => true,
            Self::AAWildType
            | Self::AASingleReplacement
            | Self::AADoubleReplacement
            | Self::AASampled => false,
        }
    }

    /// Whether this provenance is for a wild-type hazard or not. Currently returns
    /// `None` for DNA hazards because we don't preserve that information.
    ///
    /// TODO: update this to return plain bool when we add wild type information for DNA
    pub fn is_wild_type(&self) -> Option<bool> {
        match self {
            Self::DnaNormal | Self::DnaRunt => None,
            Self::AAWildType => Some(true),
            Self::AASingleReplacement | Self::AADoubleReplacement | Self::AASampled => Some(false),
        }
    }

    pub fn window_len(&self) -> usize {
        match self {
            Self::DnaNormal => shared_types::WINDOW_LENGTH_DNA_NORMAL,
            Self::DnaRunt => shared_types::WINDOW_LENGTH_DNA_RUNT,
            Self::AAWildType
            | Self::AASingleReplacement
            | Self::AADoubleReplacement
            | Self::AASampled => shared_types::WINDOW_LENGTH_AA * 3,
        }
    }

    pub fn shingle_step_size(&self) -> usize {
        match self {
            Self::DnaNormal | Self::DnaRunt => 1,
            Self::AAWildType
            | Self::AASingleReplacement
            | Self::AADoubleReplacement
            | Self::AASampled => 3,
        }
    }

    pub fn window_gap(&self, tiled: bool) -> usize {
        if tiled {
            self.window_len()
        } else {
            self.shingle_step_size()
        }
    }
}

impl TryFrom<u8> for Provenance {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::DnaNormal),
            1 => Ok(Self::AAWildType),
            2 => Ok(Self::AASingleReplacement),
            3 => Ok(Self::AADoubleReplacement),
            4 => Ok(Self::AASampled),
            5 => Ok(Self::DnaRunt),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Metadata {
    pub hlt_index: u32,
    pub an_subindex: u8,
    #[serde(serialize_with = "serialize_f16", deserialize_with = "deserialize_f16")]
    pub an_likelihood: half::f16,
    pub provenance: Provenance,
    pub reverse_screened: bool,
    pub is_common: bool,
}

fn serialize_f16<S: serde::Serializer>(v: &half::f16, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f32(v.to_f32())
}

fn deserialize_f16<'de, D: serde::Deserializer<'de>>(d: D) -> Result<half::f16, D::Error> {
    // json serializes NaN as null :,-)
    let f: Option<f32> = serde::de::Deserialize::deserialize(d)?;
    Ok(f.map(half::f16::from_f32).unwrap_or(half::f16::NAN))
}

impl From<Metadata> for u64 {
    fn from(m: Metadata) -> Self {
        //                                                                 ┌> provenance
        //                                                                 │ ┌> reverse_screened
        //                                                                 │ │┌> is_common
        //                                                                 │ ││ ┌> padding
        // [------------------HLT bits-------] [AN idx] [--likelihood---] [╵]╵╵[╵]
        // 01234567 01234567 01234567 01234567 01234567 01234567 01234567 01234567
        // 0        1        2        3        4        5        6        7
        ((m.hlt_index as u64) << 32)
            | ((m.an_subindex as u64) << 24)
            | ((m.an_likelihood.to_bits() as u64) << 8)
            | (((m.provenance as u8 as u64) << 5) & 0b11100000)
            | (((m.reverse_screened as u8 as u64) << 4) & 0b00010000)
            | (((m.is_common as u8 as u64) << 3) & 0b00001000)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum MetadataDecodeError {
    #[error("The 3 bits {:#b} are not a valid provenance", .0 & 0b111)]
    InvalidProvenance(u8),
    #[error("The 3 bits {:#b} are padding and should be zero", .0 & 0xf)]
    NonzeroPadding(u8),
}

impl TryFrom<u64> for Metadata {
    type Error = MetadataDecodeError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let hlt_index = ((value & 0xff_ff_ff_ff_00_00_00_00) >> 32) as u32;
        let an_subindex = ((value & 0x00_00_00_00_ff_00_00_00) >> 24) as u8;
        let an_likelihood = half::f16::from_bits(((value & 0x00_00_00_00_00_ff_ff_00) >> 8) as u16);
        let provenance = ((value & 0x00_00_00_00_00_00_00_e0) >> 5) as u8;
        let provenance =
            Provenance::try_from(provenance).map_err(MetadataDecodeError::InvalidProvenance)?;
        let reverse_screened = (value & 0x00_00_00_00_00_00_00_10) != 0;
        let is_common = (value & 0x00_00_00_00_00_00_00_08) != 0;
        let padding = (value & 0x00_00_00_00_00_00_00_07) as u8;
        if padding != 0 {
            return Err(MetadataDecodeError::NonzeroPadding(padding));
        }

        Ok(Self {
            hlt_index,
            an_subindex,
            an_likelihood,
            provenance,
            reverse_screened,
            is_common,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{quickcheck, Arbitrary, Gen};

    #[test]
    fn provenance_repr_is_equivalent() {
        for i in 0_u8..8 {
            if let Ok(provenance) = Provenance::try_from(i) {
                assert_eq!(provenance as u8, i);
            }
        }
    }

    #[test]
    fn no_provenance_over_3_bits() {
        for i in 8_u8..=u8::MAX {
            assert!(Provenance::try_from(i).is_err());
        }
    }

    #[test]
    fn test_110() {
        let m = Metadata::try_from(0x110);
        println!("{m:?}");
        println!("{:#x}", u64::from(m.unwrap()));
    }

    impl Arbitrary for Provenance {
        fn arbitrary(g: &mut Gen) -> Self {
            g.choose(&[
                Provenance::DnaNormal,
                Provenance::AAWildType,
                Provenance::AASingleReplacement,
                Provenance::AADoubleReplacement,
                Provenance::AASampled,
                Provenance::DnaRunt,
            ])
            .copied()
            .unwrap()
        }
    }

    impl Arbitrary for Metadata {
        fn arbitrary(g: &mut Gen) -> Self {
            Self {
                hlt_index: u32::arbitrary(g),
                an_subindex: u8::arbitrary(g),
                an_likelihood: half::f16::from_bits(u16::arbitrary(g)),
                provenance: Provenance::arbitrary(g),
                reverse_screened: bool::arbitrary(g),
                is_common: bool::arbitrary(g),
            }
        }
    }

    quickcheck! {
        fn qc_metadata_repr_is_equivalent(repr: u64) -> bool {
            if let Ok(metadata) = Metadata::try_from(repr) {
                if u64::from(metadata) != repr {
                    eprintln!("invalid trip: {repr:#x}");
                    return false;
                }
            }

            // also check with explicitly-zeroed padding, for better search efficiency
            let zeroed_padding = repr & !0xf;
            if let Ok(metadata) = Metadata::try_from(zeroed_padding) {
                if u64::from(metadata) != zeroed_padding {
                    eprintln!("invalid trip (zeroed padding): {zeroed_padding:#x}");
                    return false;
                }
            }

            true
        }

        fn qc_metadata_roundtrips(repr: Metadata) -> bool {
            let roundtripped = Metadata::try_from(u64::from(repr)).unwrap();

            // since nan != nan, we need to handle it separately
            let (repr, roundtripped) = if repr.an_likelihood.is_nan() {
                if !roundtripped.an_likelihood.is_nan() {
                    return false;
                }
                // set both to zero so we can compare the other fields
                let mut repr = repr;
                repr.an_likelihood = half::f16::from_f32(0.0);
                let mut roundtripped = roundtripped;
                roundtripped.an_likelihood = half::f16::from_f32(0.0);

                (repr, roundtripped)
            } else {
                (repr, roundtripped) // no change required
            };

            roundtripped == repr
        }
    }
}
