// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

/* Payload for screen endpoint */

use curve25519_dalek::ristretto::RistrettoPoint;
use rand::prelude::SliceRandom;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use doprf::tagged::HashTag;
use packed_ristretto::{PackableRistretto, PackedRistrettos};
use shared_types::synthesis_permission::Region;

#[derive(Serialize, Deserialize, Debug)]
struct ScreenPayload {
    fasta: String,
    region: Region,
    provider_reference: String,
}

/* Byte payloads */

pub fn screen_payload_builder(fasta: &str) -> String {
    let payload = ScreenPayload {
        fasta: fasta.to_string(),
        region: Region::All,
        provider_reference: String::from("performance_tests"),
    };
    serde_json::to_string(&payload).unwrap()
}

pub fn get_flat_random_byte_array(len: usize) -> Vec<u8> {
    let mut v = vec![];

    for ar in get_random_byte_array(len) {
        v.extend(ar);
    }

    v
}

pub fn get_tagged_random_byte_array(len: usize) -> Vec<u8> {
    let mut v = vec![];
    let mut rng = OsRng;

    for i in 0..len {
        v.extend(HashTag::new(i == 0, 0, i).as_bytes());
        v.extend(RistrettoPoint::random(&mut rng).compress().0)
    }

    v
}

pub fn get_random_byte_array(len: usize) -> Vec<[u8; 32]> {
    let mut rng = OsRng;

    (0..len)
        .map(|_| RistrettoPoint::random(&mut rng).compress().0)
        .collect()
}

pub fn get_random_packed_ristretto<T: PackableRistretto<Array = [u8; 32]>>(
    len: usize,
) -> PackedRistrettos<T> {
    PackedRistrettos::new(get_random_byte_array(len))
}

/* Sequence generator */

fn check_static_seq(len: usize, max: usize) {
    if len >= max {
        eprintln!("Specified BP length ({len}) is longer than supported for this scenario ({max})");
        std::process::exit(1);
    }
}

pub fn single_random_perm_const_len(len: usize) -> String {
    let valid_chars: [&str; 4] = ["A", "T", "C", "G"];
    let seq = String::from(
        "ATGAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATCGT\
CCCGTCAGGCCCCCTCAAAGCCGAGATCGCGCAGAGACTTGAAGATGTCTTTGCAGGGAAGAACACCGA\
TCTTGAGGCTCTCATGGAATGGCTAAAGACAAGACCAATCCTGTCACCTCTGACTAAGGGGATTTTAGG\
ATTTGTGTTCACGCTCACCGTGCCCAGTGAGCGAGGACTGCAGCGTAGACGCTTTGTC\
CAAAATGCCCTTAATGGGAACGGGGATCCAAATAACATGGACAGAGCAGTTAAACTGTAC\
AGGAAGCTTAAGAGGGAGATAACATTCCATGGGGCCAAAGAAGTAGCACTCAGTTATTCC\
GCTGGTGCACTTGCCAGTTGTATGGGCCTCATATACAACAGGATGGGGACTGTGACCACT\
GAAGTGGCATTTGGCCTGGTATGCGCAACCTGTGAACAGATTGCTGATTCCCAGCATCGG\
TCTCACAGGCAAATGGTGACAACAACCAATCCACTAATCAGACATGAGAACAGAATGGTA\
CTGGCCAGCACTACGGCTAAGGCTATGGAGCAAATGGCTGGATCGAGTGAGCAAGCAGCA\
GAGGCCATGGAGGTTGCTAGTCAGGCTAGGCAAATGGTGCAGGCGATGAGAACCATTGGG\
ACTCATCCTAGCTCCAGTGCTGGTCTGAAAGACGATCTTATTGAAAATTTGCAGGCCTAC\
CAGAAACGAATGGGGGTGCAGATGCAACGATTCAAGTGATCCTCTCGTTATTGCCGCAAG\
TATCATTGGGATCTTGCACTTGATATTGTGGATTCTTGATCGTCTTTTTTTCAAATGCAT\
TTATCGTCGCCTTAAATACGGTTTGAAAAGAGGGCCTTCTACGGAAGGAGTGCCGGAGTC\
TATGAGGGAAGAATATCGAAAGGAACAGCAGAGTGCTGTGGATGTTGACGATGGTCATTT\
TGTCAACATAGAGCTGGAGTAA",
    );

    check_static_seq(len, seq.len());

    let mut baseseq = String::from(&seq[..len]);

    // we need to mutate at least 1 character in every window size
    for idx in (0..baseseq.len()).step_by(40) {
        let replacement = valid_chars.choose(&mut rand::thread_rng()).unwrap();
        baseseq.replace_range(idx..idx + 1, replacement);
    }

    baseseq
}

pub fn single_known_hazard_const_len(len: usize) -> String {
    let seq = String::from(
        "ATGAGTCTTTTAACCGAGGTCGAAACGTACGTTCTCTCTATCGT\
CCCGTCAGGCCCCCTCAAAGCCGAGATCGCGCAGAGACTTGAAGATGTCTTTGCAGGGAAGAACACCGA\
TCTTGAGGCTCTCATGGAATGGCTAAAGACAAGACCAATCCTGTCACCTCTGACTAAGGGGATTTTAGG\
ATTTGTGTTCACGCTCACCGTGCCCAGTGAGCGAGGACTGCAGCGTAGACGCTTTGTC\
CAAAATGCCCTTAATGGGAACGGGGATCCAAATAACATGGACAGAGCAGTTAAACTGTAC\
AGGAAGCTTAAGAGGGAGATAACATTCCATGGGGCCAAAGAAGTAGCACTCAGTTATTCC\
GCTGGTGCACTTGCCAGTTGTATGGGCCTCATATACAACAGGATGGGGACTGTGACCACT\
GAAGTGGCATTTGGCCTGGTATGCGCAACCTGTGAACAGATTGCTGATTCCCAGCATCGG\
TCTCACAGGCAAATGGTGACAACAACCAATCCACTAATCAGACATGAGAACAGAATGGTA\
CTGGCCAGCACTACGGCTAAGGCTATGGAGCAAATGGCTGGATCGAGTGAGCAAGCAGCA\
GAGGCCATGGAGGTTGCTAGTCAGGCTAGGCAAATGGTGCAGGCGATGAGAACCATTGGG\
ACTCATCCTAGCTCCAGTGCTGGTCTGAAAGACGATCTTATTGAAAATTTGCAGGCCTAC\
CAGAAACGAATGGGGGTGCAGATGCAACGATTCAAGTGATCCTCTCGTTATTGCCGCAAG\
TATCATTGGGATCTTGCACTTGATATTGTGGATTCTTGATCGTCTTTTTTTCAAATGCAT\
TTATCGTCGCCTTAAATACGGTTTGAAAAGAGGGCCTTCTACGGAAGGAGTGCCGGAGTC\
TATGAGGGAAGAATATCGAAAGGAACAGCAGAGTGCTGTGGATGTTGACGATGGTCATTT\
TGTCAACATAGAGCTGGAGTAA",
    );

    check_static_seq(len, seq.len());
    String::from(&seq[..len])
}

pub fn single_random_sequence_of_size(size: usize) -> String {
    let valid_chars: [&str; 4] = ["A", "T", "C", "G"];

    let mut sequence: Vec<&str> = vec![];
    for _iter in 0..size {
        sequence.extend(valid_chars.choose(&mut rand::thread_rng()));
    }

    sequence.into_iter().collect()
}
