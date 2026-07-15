// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The internal HDB<>synthclient API.

use serde::{Deserialize, Serialize};

use pipeline_bridge::{OrganismType, Tag};
use shared_types::{server_versions::HdbVersion, synthesis_permission::SynthesisPermission};

pub mod verification;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct HdbScreeningResult {
    #[serde(flatten)]
    pub base: BaseHdbScreeningResult,
    pub verification: Option<HdbVerification>,
}

impl HdbScreeningResult {
    pub fn base(base: BaseHdbScreeningResult) -> Self {
        Self {
            base,
            verification: None,
        }
    }

    pub fn blank() -> Self {
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();

        Self::base(BaseHdbScreeningResult {
            results: vec![],
            debug_hdb_responses: None,
            provider_reference: None,
            timestamp,
            hdb_version: HdbVersion {
                server_version: "(request did not reach hdb)".to_string(),
                hdb_timestamp: None,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BaseHdbScreeningResult {
    pub results: Vec<ConsolidatedHazardResult>,
    pub debug_hdb_responses: Option<Vec<DebugSeqHdbResponse>>,
    pub provider_reference: Option<String>,
    pub timestamp: String,
    pub hdb_version: HdbVersion,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct HdbVerification {
    /// The version string of synthclient requesting this order. This is the
    /// same string as returned by `GET /version`, containing a version number
    /// and a commit hash, like "1.2.3-a4b5c6d" or "1.2.3-dev-a4b5c6d".
    pub synthclient_version: String,
    /// String containing the exact BaseHdbScreeningResult JSON for `result`
    /// that was signed over. This is somewhat redundant: it will be always
    /// equivalent to a minified version of the parent object with the
    /// `signature` field removed. But this way is more convenient, and there is
    /// no ambiguity about how the hash was computed.
    pub result_json: String,
    /// The result of signing `result_json` with a keypair.
    pub signature: String,
    /// The public key of the keypair `signature` was created with.
    pub public_key: String,
    /// The signature history URL, for certificate transparency.
    pub history: String,
    /// A hex digest of the SHA3-256 hash of the JSON request posted to
    /// synthclient.
    ///
    /// This field is a bit of a misnomer: the hash is not just over a FASTA,
    /// but over a larger JSON object also containing region and exemption data.
    pub fasta_sha3_256_hex: String,
    /// The SHA3-256 hash over the concatenation of:
    ///
    /// * `synthclient_version`
    /// * `result_json`
    /// * `signature`
    /// * `public_key`
    /// * `history`
    /// * `fasta_sha3_256_hex`
    pub sha3_256: String,
}

/// Consolidated Result of DOPRF on contiguous sequences that were contained in the HDB
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Ord, PartialOrd)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
pub struct Organism {
    pub name: String,
    pub organism_type: OrganismType,
    pub ans: Vec<String>,
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Ord, PartialOrd)]
pub struct HitRegion {
    /// Index (in the original sequence) of the start of the hit region
    pub seq_range_start: usize,
    /// Index (in the original sequence) of the end of the hit region range
    /// This range bound is exclusive.
    pub seq_range_end: usize,
}

/// Result of DOPRF on a sequence that was contained in the HDB.
/// Debug only
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// for backwards compatibility with old clients, test that a `HdbScreeningResult::Base`
    /// can be deserialized as a `BaseHdbScreeningResult` (which used to be the definition
    /// of `HdbScreeningResult` before verifiable screening was implemented)
    #[test]
    fn hdb_response_backwards_compat() {
        let hsr = HdbScreeningResult::base(BaseHdbScreeningResult {
            results: vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![],
                synthesis_permission: SynthesisPermission::Denied,
                most_likely_organism: Organism {
                    name: "Testitis".to_owned(),
                    organism_type: OrganismType::Fungus,
                    ans: vec!["{}".to_owned()],
                    tags: vec![],
                },
                organisms: vec![Organism {
                    name: "Testitis".to_owned(),
                    organism_type: OrganismType::Fungus,
                    ans: vec!["{}".to_owned()],
                    tags: vec![],
                }],
                is_dna: true,
                is_wild_type: None,
                exempt: false,
            }],
            debug_hdb_responses: None,
            provider_reference: Some("test".to_owned()),
            timestamp: "2024-05-29T12:00:00Z".to_owned(),
            hdb_version: HdbVersion {
                server_version: "foo".to_owned(),
                hdb_timestamp: None,
            },
        });

        let json = serde_json::to_string(&hsr).unwrap();
        println!("{json}");

        let base: BaseHdbScreeningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(base, hsr.base);

        let total: HdbScreeningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(total.base, hsr.base);
        assert_eq!(total.verification, None);
    }
}
