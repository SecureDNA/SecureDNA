// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use quickdna::{BaseSequence, DnaSequence, FastaParser, Nucleotide, NucleotideAmbiguous};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

/// Translate a DNA string into amino acids.
#[wasm_bindgen]
pub fn translate(dna: &str) -> Result<String, JsError> {
    match DnaSequence::<NucleotideAmbiguous>::from_str(dna) {
        Ok(dna) => {
            let protein = dna.translate(quickdna::TranslationTable::Ncbi1);
            Ok(String::from_utf8(protein.as_slice().to_vec())?)
        }
        Err(_) => Err(JsError::new("DNA string is invalid")),
    }
}

/// Parse a FASTA string.
///
/// * On success, return an array of FastaRecords.
/// * On error, return a string describing the error.
#[wasm_bindgen]
pub fn parse_fasta(fasta: &str) -> JsValue {
    let parser = FastaParser::<DnaSequence<Nucleotide>>::default();
    let records = match parser.parse_str(fasta) {
        Ok(records) => records,
        Err(e) => return JsValue::from(e.to_string()),
    };
    serde_wasm_bindgen::to_value(&records).unwrap()
}
