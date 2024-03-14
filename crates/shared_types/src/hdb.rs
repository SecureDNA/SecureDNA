// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The internal HDB<>synthclient API.

use pipeline_bridge::{OrganismType, Tag};
use serde::{Deserialize, Serialize};

use crate::synthesis_permission::SynthesisPermission;

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct HdbScreeningResult {
    pub results: Vec<ConsolidatedHazardResult>,
    pub debug_hdb_responses: Option<Vec<DebugSeqHdbResponse>>,
    pub provider_reference: Option<String>,
}

/// Consolidated Result of DOPRF on contiguous sequences that were contained in the HDB
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ConsolidatedHazardResult {
    pub record: u64,
    /// Indexes marking the beginning and end of the hit region, as well as the index of the last
    /// window in the range.
    pub hit_regions: Vec<HitRegion>,
    pub synthesis_permission: SynthesisPermission,
    pub most_likely_organism: Organism,
    pub organisms: Vec<Organism>,
    pub is_dna: bool,
    pub is_wild_type: Option<bool>,
    pub exempt: bool,
}

// An organism definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Organism {
    pub name: String,
    pub organism_type: OrganismType,
    pub ans: Vec<String>,
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct HitRegion {
    /// Index (in the original sequence) of the start of the hit region
    pub seq_range_start: usize,
    /// Index (in the original sequence) of the end of the hit region range. This range bound is
    /// exclusive.
    pub seq_range_end: usize,
}

/// Result of DOPRF on a sequence that was contained in the HDB.
/// Debug only
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct DebugSeqHdbResponse {
    pub record: u64,
    /// Index (in the original sequence) of the start of the hit
    pub seq_range_start: usize,
    /// Index (in the original sequence) of the end (exclusive) of the hit
    pub seq_range_end: usize,
    pub synthesis_permission: SynthesisPermission,
    pub most_likely_organism: Organism,
    pub organisms: Vec<Organism>,
    pub an_likelihood: f32,
    pub provenance: Provenance,
    pub reverse_screened: bool,
    pub window_gap: usize,
    pub exempt: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash, Serialize, Deserialize)]
/// The provenance of a database entry.
pub enum Provenance {
    DnaNormal,
    AAWildType,
    AASingleReplacement,
    AADoubleReplacement,
    AASampled,
    DnaRunt,
}
