// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use shared_types::hdb;

use super::types::HitOrganism;

/// SecureDNA-specific metadata for the response, which we don't expect to expose in later
/// versions.
#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub struct DebugInfo {
    pub grouped_hits: Vec<DebugFastaRecordHits>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub struct DebugFastaRecordHits {
    pub fasta_header: String,
    pub line_number_range: (u64, u64),
    pub sequence_length: u64,
    pub hits: Vec<DebugHit>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub struct DebugHit {
    pub seq: String,
    pub index: u64,
    pub most_likely_organism: HitOrganism,
    pub organisms: Vec<HitOrganism>,
    pub an_likelihood: f32,
    pub provenance: SequenceProvenance,
    pub reverse_screened: bool,
    pub window_gap: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub enum SequenceProvenance {
    DnaNormal,
    DnaRunt,
    AAWildType,
    AASingleReplacement,
    AADoubleReplacement,
    AASampled,
}

impl From<hdb::Provenance> for SequenceProvenance {
    fn from(value: hdb::Provenance) -> Self {
        match value {
            hdb::Provenance::DnaNormal => Self::DnaNormal,
            hdb::Provenance::DnaRunt => Self::DnaRunt,
            hdb::Provenance::AAWildType => Self::AAWildType,
            hdb::Provenance::AASingleReplacement => Self::AASingleReplacement,
            hdb::Provenance::AADoubleReplacement => Self::AADoubleReplacement,
            hdb::Provenance::AASampled => Self::AASampled,
        }
    }
}

impl DebugHit {
    pub fn from_hdb_response(hdb_response: hdb::DebugSeqHdbResponse, dna: &str) -> Self {
        Self {
            seq: dna[hdb_response.seq_range_start..hdb_response.seq_range_end].to_string(),
            index: hdb_response.seq_range_start as u64,
            most_likely_organism: hdb_response.most_likely_organism.clone().into(),
            organisms: hdb_response
                .organisms
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
            an_likelihood: hdb_response.an_likelihood,
            provenance: hdb_response.provenance.into(),
            reverse_screened: hdb_response.reverse_screened,
            window_gap: hdb_response.window_gap,
        }
    }
}
