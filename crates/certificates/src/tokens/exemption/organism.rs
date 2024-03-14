// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use quickdna::{
    DnaSequence, FastaFile, FastaParseError, FastaParseSettings, FastaParser, Located,
    NucleotideAmbiguous, TranslationError,
};
use rasn::de::Error;
use rasn::types::{Constraints, OctetString, Utf8String};
use rasn::{AsnType, Decode, Encode, Encoder, Tag};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use thiserror::Error;

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
// tsgen
#[rasn(automatic_tags)]
pub struct GenbankId(String);

impl Display for GenbankId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl GenbankId {
    pub fn try_new<T: Into<String>>(id: T) -> Result<Self, ParseGenbankIdError> {
        id.into().try_into()
    }
}

#[derive(Error, Debug)]
pub enum ParseGenbankIdError {
    #[error("Invalid, contained non ASCII characters)")]
    NonASCII,
}

impl TryFrom<String> for GenbankId {
    type Error = ParseGenbankIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_ascii() {
            Ok(Self(value.to_ascii_uppercase()))
        } else {
            Err(ParseGenbankIdError::NonASCII)
        }
    }
}

#[derive(Debug, Clone, Eq, Deserialize, Serialize)]
// tsgen
pub struct Sequence(FastaFile<DnaSequence<NucleotideAmbiguous>>);

impl Sequence {
    pub fn try_new<T: Into<String>>(
        seq: T,
    ) -> Result<Self, Located<FastaParseError<TranslationError>>> {
        seq.into().try_into()
    }
}

impl TryFrom<String> for Sequence {
    type Error = Located<FastaParseError<TranslationError>>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parser_settings = FastaParseSettings::new()
            .concatenate_headers(true)
            .allow_preceding_comment(false);
        let fasta_file = FastaParser::<DnaSequence<NucleotideAmbiguous>>::new(parser_settings)
            .parse_str(&value)?;
        Ok(Sequence(fasta_file))
    }
}

impl PartialEq for Sequence {
    fn eq(&self, other: &Self) -> bool {
        self.0.records.len() == other.0.records.len()
            && self
                .0
                .records
                .iter()
                .zip(other.0.records.iter())
                .all(|(s, o)| s.header == o.header && s.contents == o.contents)
    }
}

impl Hash for Sequence {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_string().hash(state)
    }
}

impl AsnType for Sequence {
    const TAG: Tag = Tag::OCTET_STRING;
}

impl rasn::Encode for Sequence {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<(), E::Error> {
        encoder
            .encode_octet_string(tag, constraints, self.0.to_string().as_bytes())
            .map(drop)
    }
}

impl Decode for Sequence {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let bytes = OctetString::decode_with_tag_and_constraints(decoder, tag, constraints)?;

        let string = Utf8String::from_utf8_lossy(&bytes);
        Sequence::try_new(string)
            .map_err(|err| D::Error::custom(format!("Invalid encoding for Sequence: {}", err)))
    }
}

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
// tsgen
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum SequenceIdentifier {
    Dna(Sequence),
    Id(GenbankId),
}

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
// tsgen
#[rasn(automatic_tags)]
pub struct Organism {
    pub name: String,
    pub sequences: Vec<SequenceIdentifier>,
}

impl Organism {
    pub fn new<T: Into<String>>(name: T, sequences: Vec<SequenceIdentifier>) -> Self {
        Self {
            name: name.into(),
            sequences,
        }
    }
}

#[cfg(test)]
mod tests {
    use rasn::der;

    use super::*;

    #[test]
    fn can_asn_encode_and_decode_sequence() {
        let string = ">Virus1\nAC\nT\n>Empty\n\n>Virus2\n>with many\n>comment lines\nC  AT";
        let seq = Sequence::try_new(string).unwrap();

        let encoded = der::encode(&seq).unwrap();
        let decoded = der::decode::<Sequence>(&encoded).unwrap();

        assert_eq!(seq, decoded)
    }

    #[test]
    fn can_asn_encode_and_decode_nested_sequence() {
        let string = ">Virus1\nAC\nT\n>Empty\n\n>Virus2\n>with many\n>comment lines\nC  AT";
        let seq = Sequence::try_new(string).unwrap();
        let seq_identifier = SequenceIdentifier::Dna(seq);

        let organism = Organism::new("Virus1", vec![seq_identifier]);

        let encoded = der::encode(&organism).unwrap();
        let decoded = der::decode::<Organism>(&encoded).unwrap();

        assert_eq!(organism, decoded)
    }
}
