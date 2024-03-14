// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Temporary module for consolidating windows/hits.
//!
//! A hit will be consolidated into a hit region; all the hits in this region will share the same metadata,
//! and the window indexes will also be consolidated to a "start" and "end".
//!
//! When the hdb_responses are returned in order (which we assume), the logic is fairly
//! straightforward, so the simplest logic is implemented without abstraction or further
//! compartmentalization. This should make porting to hdb easy when necessary in the future.
//!
//! Reverse-screened tag will be dealt with in synthclient.
//!
//! ## Provenance
//!
//! We won't mix AA and DNA hits.
//!
//! However, with DNA, should we mix runts and hogs? For now, no.
//!
//! ## Window order
//!
//! Both the input and output window order is determined by the hash type descriptor vector (HTDV),
//! which is negotiated between the client and DB during mutual authentication. See the \[\[SCEP\]\] article
//! on the wiki for more information.
//!
//! ## Overlaps
//!
//! We are not checking if sequences overlap, only sequence indexes. Checked some real-world
//! examples, and so far it looks like checking overlap is not particularly helpful, as for viruses
//! there's a large gap between contiguous sequences.
//!
//! For bacteria and fungi, there's an additional problem. When constructing the database, these
//! hazards are tiled rather than shingled because of their size. The customer's order is always
//! shingled, though. So when hitting a bacterium/fungus, we expect the hits to be spaced into tiles.
//! Thus we must be more lenient when consolidating bacteria/fungi. This is done by allowing a margin
//! of `window_gap` between hits, which is 1 or 3bp for shingled hits but 30bp~42bp when the hit
//! is bacterial/fungal.
//!
//! ## an_likelihood
//!
//! an_likelihood is a logprob, so during consolidation we sum across any hits which share metadata
//! (first during hit region consolidation, and then when grouping by metadata)

use doprf::tagged::HashTag;
use indexmap::IndexMap;

use crate::{response::HdbOrganism, HdbResponse, Provenance};
use serde::{Deserialize, Serialize};
use shared_types::{
    hash::{HashSpec, HashTypeDescriptor},
    hdb as hdb_api,
    synthesis_permission::SynthesisPermission,
};
use thiserror::Error;

/// Consolidated Result of DOPRF on contiguous sequences that were contained in the HDB
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct ConsolidatedHazardResult {
    /// Fasta record this result is for
    pub record: u64,
    /// Indexes marking the beginning and end of the hit region, as well as the index of the last
    /// window in the range.
    pub hit_regions: Vec<HitRegion>,
    /// Aggregated response from the HDB
    pub hdb_response: HdbResponse,
}

/// Indexes marking the beginning and end of the hit region, as well as the index of the last
/// window in the range.
///
/// An example (with arbitrary window size 20)
///
/// ```text
/// seq_range_start          last_window_start   seq_range_end
/// ▼                        ▼                   ▼
/// AAAAAAAAAAAAAAAAAAAATTTTTCCCCCCCCCCCCCCCCCCCC
/// ────────────────────
///      one window
///
/// window_size = 20
/// seq_range_start = 0
/// seq_range_end = 45
/// last_window_start = 25
/// ```
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct HitRegion {
    /// Index (in the original sequence) of the start of the hit region
    pub seq_range_start: usize,
    /// Index (in the original sequence) of the end of the hit region range. This range bound is
    /// exclusive.
    pub seq_range_end: usize,
    /// Index (in the original sequence) of the start of the last window in the hit region
    pub last_window_start: usize,
    /// Debug usage only, not intended for API output. The number of windows within the hit region.
    pub window_count: usize,
}

/// Result of DOPRF on a sequence that was contained in the HDB.
/// Debug only
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct DebugSeqHdbResponse {
    /// Fasta record this result is for
    pub record: u64,
    /// Index (in the original sequence) of the start of the hit
    pub seq_range_start: usize,
    /// Index (in the original sequence) of the end (exclusive) of the hit
    pub seq_range_end: usize,
    pub hdb_response: HdbResponse,
}

#[derive(Debug, Error, PartialEq, Serialize)]
pub enum ConsolidationError {
    #[error("bad hash type index {index} into HTDV of length {length}")]
    BadHashTypeIndex { index: usize, length: usize },
}

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Consolidation {
    pub results: Vec<ConsolidatedHazardResult>,
    pub debug_hdb_responses: Option<Vec<DebugSeqHdbResponse>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashId {
    // Realistically u64 is overkill, but it's an easy way to ensure overflow is categorically
    // impossible because the maximum request size is u64::MAX / size_of::<TaggedHash>.
    pub record: u64,
    // HashTag only supports sequence positions up to 24 bits, so this guarantees support for
    // all of them.
    pub index_in_record: u32,
    pub hash_type_index: u8,
}

impl HashId {
    pub fn new(hash_tag: HashTag, previous_record: Option<u64>) -> Self {
        Self {
            record: previous_record
                .map(|r| r + hash_tag.starts_new_record() as u64)
                .unwrap_or_default(),
            index_in_record: hash_tag
                .index_in_record()
                .try_into()
                .expect("HashTag only supports 24-bit seq indexes so it should fit in a u32"),
            hash_type_index: hash_tag.hash_type_index(),
        }
    }
}

/// Consolidate hits into hit regions.
///
/// `hdb_responses` should iterate over [HdbResponse]s paired with the HashTag
/// of the hash that generated the response.
///
/// Hits are consolidated into the same `ConsolidatedHazardResult` if they are
/// close enough and all their metadata matches up. Hits are considered close
/// enough if they are within the `window_gap` of the hazard they hit; this
/// means hits for tiled (fungal/bacterial) organisms consolidate more easily
/// than hits for viral organisms.
///
pub fn consolidate_windows(
    hdb_responses: impl Iterator<Item = (HashId, HdbResponse)>,
    hash_spec: &HashSpec,
    debug: bool,
) -> Result<Consolidation, ConsolidationError> {
    // Iterating over each window's query_index and hdb_response
    //
    // If:
    // - current has the same metadata (aka `hdb_response` here) as `last`
    // - current window is last index + next_contiguous_index (1 for dna, 3 for aa)
    //
    // Then:
    // - update `last` with current's additional index.
    //
    // Else:
    // - add a new ConsolidatedHazardResult to the end of `res`
    //
    // Assumes that hdb_responses are in order.

    let mut debug_responses = vec![];

    let mut res: Vec<ConsolidatedHits> = vec![];
    for (hash_id, hdb_response) in hdb_responses {
        let index = hash_id.hash_type_index as usize;
        let htdv = &hash_spec.htdv;
        let htd = htdv
            .get(index)
            .ok_or(ConsolidationError::BadHashTypeIndex {
                index,
                length: htdv.len(),
            })?;

        let seq_position = hash_id.index_in_record as usize;

        if debug {
            debug_responses.push(DebugSeqHdbResponse {
                record: hash_id.record,
                seq_range_start: seq_position,
                seq_range_end: seq_position + htd.width_bp(),
                hdb_response: hdb_response.clone(),
            });
        }

        let window_len = hdb_response.provenance.window_len();
        let seq_range_start = seq_position;
        let seq_range_end = seq_position + window_len;
        let last_window_start = seq_position;

        if let Some(last) = res.last_mut() {
            let margin = hdb_response.window_gap;
            let is_contiguous = seq_range_start <= last.hit_region.last_window_start + margin;

            if htd == &last.htd
                && is_contiguous
                && hdb_response.eq_without_an_likelihood(&last.hdb_response)
                && hash_id.record == last.record
            {
                last.hit_region.window_count += 1;

                last.hit_region.last_window_start = last_window_start;
                last.hit_region.seq_range_end = seq_range_end;

                // We sum an_likelihood when consolidating hits
                last.hdb_response.an_likelihood += hdb_response.an_likelihood;

                // Early continue only if there's a hit consolidation
                continue;
            }
        }

        // If not hit consolidation, then push a new hit region

        res.push(ConsolidatedHits {
            record: hash_id.record,
            hit_region: HitRegion {
                seq_range_start,
                seq_range_end,
                last_window_start,
                window_count: 1,
            },
            hdb_response,
            htd: htd.clone(),
        });
    }

    // Group again by metadata (GroupKey, which is like HdbResponse w/out an_likelihood)
    //
    // The f32 is an_likelihood, which we sum while iterating.
    let mut meta2hits: IndexMap<GroupKey, (f32, Vec<HitRegion>)> = IndexMap::new();
    for consolidated_hits in res {
        let an_likelihood = consolidated_hits.hdb_response.an_likelihood;
        let group_key = GroupKey::new(consolidated_hits.record, consolidated_hits.hdb_response);

        let (consolidated_an_likelihood, mapped_hit_regions) =
            meta2hits.entry(group_key).or_default();
        mapped_hit_regions.push(consolidated_hits.hit_region);
        *consolidated_an_likelihood += an_likelihood;
    }

    let consolidated_hazard_results: Vec<ConsolidatedHazardResult> = meta2hits
        .into_iter()
        .map(
            |(group_key, (consolidated_an_likelihood, hit_regions))| ConsolidatedHazardResult {
                record: group_key.record,
                hit_regions,
                hdb_response: HdbResponse {
                    synthesis_permission: group_key.synthesis_permission,
                    most_likely_organism: group_key.most_likely_organism,
                    organisms: group_key.organisms,
                    an_likelihood: consolidated_an_likelihood,
                    provenance: group_key.provenance,
                    reverse_screened: group_key.reverse_screened,
                    window_gap: group_key.window_gap,
                    exempt: group_key.exempt,
                },
            },
        )
        .collect();

    Ok(Consolidation {
        results: consolidated_hazard_results,
        debug_hdb_responses: if debug { Some(debug_responses) } else { None },
    })
}

struct ConsolidatedHits {
    record: u64,
    hdb_response: HdbResponse,
    hit_region: HitRegion,
    htd: HashTypeDescriptor,
}

/// Basically HdbResponse without an_likelihood, used as key for grouping hit regions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct GroupKey {
    pub record: u64,
    pub synthesis_permission: SynthesisPermission,
    pub most_likely_organism: HdbOrganism,
    pub organisms: Vec<HdbOrganism>,
    pub provenance: Provenance,
    pub reverse_screened: bool,
    pub window_gap: usize,
    pub exempt: bool,
}

impl GroupKey {
    fn new(record: u64, hdb_response: HdbResponse) -> Self {
        Self {
            record,
            synthesis_permission: hdb_response.synthesis_permission,
            most_likely_organism: hdb_response.most_likely_organism,
            organisms: hdb_response.organisms,
            provenance: hdb_response.provenance,
            reverse_screened: hdb_response.reverse_screened,
            window_gap: hdb_response.window_gap,
            exempt: hdb_response.exempt,
        }
    }
}

impl Consolidation {
    pub fn to_hdb_screening_result(
        self,
        provider_reference: Option<String>,
    ) -> hdb_api::HdbScreeningResult {
        fn into_organism(hdb_organism: HdbOrganism) -> hdb_api::Organism {
            let HdbOrganism {
                name,
                organism_type,
                ans,
                tags,
            } = hdb_organism;
            hdb_api::Organism {
                name,
                organism_type,
                ans,
                tags,
            }
        }

        hdb_api::HdbScreeningResult {
            results: self
                .results
                .into_iter()
                .filter_map(|x| {
                    if x.hdb_response.reverse_screened {
                        None
                    } else {
                        Some(hdb_api::ConsolidatedHazardResult {
                            record: x.record,
                            hit_regions: x
                                .hit_regions
                                .into_iter()
                                .map(|x| hdb_api::HitRegion {
                                    seq_range_start: x.seq_range_start,
                                    seq_range_end: x.seq_range_end,
                                })
                                .collect(),
                            synthesis_permission: x.hdb_response.synthesis_permission,
                            most_likely_organism: into_organism(
                                x.hdb_response.most_likely_organism,
                            ),
                            organisms: x
                                .hdb_response
                                .organisms
                                .into_iter()
                                .map(into_organism)
                                .collect(),
                            is_dna: x.hdb_response.provenance.is_dna(),
                            is_wild_type: x.hdb_response.provenance.is_wild_type(),
                            exempt: x.hdb_response.exempt,
                        })
                    }
                })
                .collect(),
            debug_hdb_responses: self.debug_hdb_responses.map(|responses| {
                responses
                    .into_iter()
                    .map(|x| hdb_api::DebugSeqHdbResponse {
                        record: x.record,
                        seq_range_start: x.seq_range_start,
                        seq_range_end: x.seq_range_end,
                        synthesis_permission: x.hdb_response.synthesis_permission,
                        most_likely_organism: into_organism(x.hdb_response.most_likely_organism),
                        organisms: x
                            .hdb_response
                            .organisms
                            .into_iter()
                            .map(into_organism)
                            .collect(),
                        an_likelihood: x.hdb_response.an_likelihood,
                        provenance: match x.hdb_response.provenance {
                            Provenance::DnaNormal => hdb_api::Provenance::DnaNormal,
                            Provenance::AAWildType => hdb_api::Provenance::AAWildType,
                            Provenance::AASingleReplacement => {
                                hdb_api::Provenance::AASingleReplacement
                            }
                            Provenance::AADoubleReplacement => {
                                hdb_api::Provenance::AADoubleReplacement
                            }
                            Provenance::AASampled => hdb_api::Provenance::AASampled,
                            Provenance::DnaRunt => hdb_api::Provenance::DnaRunt,
                        },
                        reverse_screened: x.hdb_response.reverse_screened,
                        window_gap: x.hdb_response.window_gap,
                        exempt: x.hdb_response.exempt,
                    })
                    .collect()
            }),
            provider_reference,
        }
    }
}

/// Some unit tests for window consolidation
#[cfg(test)]
mod test {
    use std::num::NonZeroUsize;

    use shared_types::hash::HashTypeDescriptor;

    use super::*;

    #[test]
    fn test_window_consolidation_basic() {
        let spec = &HashSpec {
            max_expansions_per_window: NonZeroUsize::MIN,
            htdv: vec![HashTypeDescriptor::dna_normal_fw()],
        };

        let hdb_response = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: HdbOrganism {
                name: "Test Hazard".into(),
                organism_type: pipeline_bridge::OrganismType::Bacterium,
                ans: vec![],
                tags: vec![],
            },
            organisms: vec![],
            an_likelihood: 1.0,
            provenance: Provenance::DnaNormal,
            reverse_screened: false,
            window_gap: 1,
            exempt: false,
        };

        // empty
        assert_eq!(
            consolidate_windows([].into_iter(), spec, false)
                .unwrap()
                .results,
            vec![]
        );
        // 1 window
        assert_eq!(
            consolidate_windows(
                [(
                    HashId {
                        record: 0,
                        index_in_record: 0,
                        hash_type_index: 0,
                    },
                    hdb_response.clone()
                )]
                .into_iter(),
                spec,
                false
            )
            .unwrap()
            .results,
            vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![HitRegion {
                    seq_range_start: 0,
                    seq_range_end: 42,
                    last_window_start: 0,
                    window_count: 1,
                }],
                hdb_response: hdb_response.clone(),
            }]
        );
        // 2 windows consecutive consolidates
        assert_eq!(
            consolidate_windows(
                [
                    (
                        HashId {
                            record: 0,
                            index_in_record: 0,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 1,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    )
                ]
                .into_iter(),
                spec,
                false
            )
            .unwrap()
            .results,
            vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![HitRegion {
                    seq_range_start: 0,
                    seq_range_end: 43,
                    last_window_start: 1,
                    window_count: 2,
                }],
                hdb_response: HdbResponse {
                    an_likelihood: 2.0,
                    ..hdb_response.clone()
                }
            },]
        );
        // 2 windows non-consecutive does not consolidate
        assert_eq!(
            consolidate_windows(
                [
                    (
                        HashId {
                            record: 0,
                            index_in_record: 0,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 2,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    )
                ]
                .into_iter(),
                spec,
                false
            )
            .unwrap()
            .results,
            vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![
                    HitRegion {
                        seq_range_start: 0,
                        seq_range_end: 42,
                        last_window_start: 0,
                        window_count: 1,
                    },
                    HitRegion {
                        seq_range_start: 2,
                        seq_range_end: 44,
                        last_window_start: 2,
                        window_count: 1,
                    }
                ],
                hdb_response: HdbResponse {
                    an_likelihood: 2.0,
                    ..hdb_response.clone()
                }
            }]
        );
        // 1 window, gap, then 2 windows consecutive
        assert_eq!(
            consolidate_windows(
                [
                    (
                        HashId {
                            record: 0,
                            index_in_record: 0,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 2,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 3,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    )
                ]
                .into_iter(),
                spec,
                false
            )
            .unwrap()
            .results,
            vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![
                    HitRegion {
                        seq_range_start: 0,
                        seq_range_end: 42,
                        last_window_start: 0,
                        window_count: 1,
                    },
                    HitRegion {
                        seq_range_start: 2,
                        seq_range_end: 45,
                        last_window_start: 3,
                        window_count: 2,
                    }
                ],
                hdb_response: HdbResponse {
                    an_likelihood: 3.0,
                    ..hdb_response
                }
            }]
        );
    }

    #[test]
    fn test_window_consolidation_tiled() {
        let spec = &HashSpec {
            max_expansions_per_window: NonZeroUsize::MIN,
            htdv: vec![HashTypeDescriptor::dna_runt_fw()],
        };

        let hdb_response = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: HdbOrganism {
                name: "Test Hazard".into(),
                organism_type: pipeline_bridge::OrganismType::Bacterium,
                ans: vec![],
                tags: vec![],
            },
            organisms: vec![],
            an_likelihood: 1.0,
            provenance: Provenance::DnaRunt,
            reverse_screened: false,
            window_gap: 30,
            exempt: false,
        };

        // Exact tiles
        assert_eq!(
            consolidate_windows(
                [
                    (
                        HashId {
                            record: 0,
                            index_in_record: 0,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 30,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 60,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    )
                ]
                .into_iter(),
                spec,
                false
            )
            .unwrap()
            .results,
            vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![HitRegion {
                    seq_range_start: 0,
                    seq_range_end: 90,
                    last_window_start: 60,
                    window_count: 3,
                }],
                hdb_response: HdbResponse {
                    an_likelihood: 3.0,
                    ..hdb_response.clone()
                },
            }]
        );
        // Dithered tiles
        assert_eq!(
            consolidate_windows(
                [
                    (
                        HashId {
                            record: 0,
                            index_in_record: 0,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 29,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 59,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    )
                ]
                .into_iter(),
                spec,
                false
            )
            .unwrap()
            .results,
            vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![HitRegion {
                    seq_range_start: 0,
                    seq_range_end: 89,
                    last_window_start: 59,
                    window_count: 3,
                }],
                hdb_response: HdbResponse {
                    an_likelihood: 3.0,
                    ..hdb_response
                },
            }]
        );
    }

    #[test]
    fn test_window_consolidation_rc() {
        let spec = &HashSpec {
            max_expansions_per_window: NonZeroUsize::MIN,
            htdv: vec![
                HashTypeDescriptor::dna_runt_fw(),
                HashTypeDescriptor::dna_runt_rc(),
            ],
        };

        let hdb_response = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: HdbOrganism {
                name: "Test Hazard".into(),
                organism_type: pipeline_bridge::OrganismType::Bacterium,
                ans: vec![],
                tags: vec![],
            },
            organisms: vec![],
            an_likelihood: 1.0,
            provenance: Provenance::DnaRunt,
            reverse_screened: false,
            window_gap: 30,
            exempt: false,
        };

        assert_eq!(
            consolidate_windows(
                [
                    (
                        HashId {
                            record: 0,
                            index_in_record: 0,
                            hash_type_index: 0,
                        },
                        hdb_response.clone()
                    ),
                    (
                        HashId {
                            record: 1,
                            index_in_record: 0,
                            hash_type_index: 1,
                        },
                        hdb_response.clone()
                    )
                ]
                .into_iter(),
                spec,
                false
            )
            .unwrap()
            .results,
            vec![
                ConsolidatedHazardResult {
                    record: 0,
                    hit_regions: vec![HitRegion {
                        seq_range_start: 0,
                        seq_range_end: 30,
                        last_window_start: 0,
                        window_count: 1,
                    },],
                    hdb_response: HdbResponse {
                        an_likelihood: 1.0,
                        ..hdb_response.clone()
                    }
                },
                ConsolidatedHazardResult {
                    record: 1,
                    hit_regions: vec![HitRegion {
                        seq_range_start: 0,
                        seq_range_end: 30,
                        last_window_start: 0,
                        window_count: 1,
                    }],
                    hdb_response: HdbResponse {
                        an_likelihood: 1.0,
                        ..hdb_response
                    }
                }
            ]
        );
    }

    #[test]
    fn test_window_consolidation_complex() {
        let spec = &HashSpec {
            max_expansions_per_window: NonZeroUsize::MIN,
            htdv: vec![
                HashTypeDescriptor::dna_normal_fw(),
                HashTypeDescriptor::dna_runt_rc(),
                HashTypeDescriptor::aa0_fw(),
                HashTypeDescriptor::dna_runt_fw(),
            ],
        };

        let organism = HdbOrganism {
            name: "Test Hazard".into(),
            organism_type: pipeline_bridge::OrganismType::Bacterium,
            ans: vec![],
            tags: vec![],
        };

        let hdb_response_hog = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: organism.clone(),
            organisms: vec![],
            an_likelihood: 1.0,
            provenance: Provenance::DnaNormal,
            reverse_screened: false,
            window_gap: 1,
            exempt: false,
        };
        let hdb_response_runt = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: organism.clone(),
            organisms: vec![],
            an_likelihood: 1.0,
            provenance: Provenance::DnaRunt,
            reverse_screened: false,
            window_gap: 1,
            exempt: false,
        };
        let hdb_response_aa = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: organism.clone(),
            organisms: vec![],
            an_likelihood: 1.0,
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            window_gap: 3,
            exempt: false,
        };
        let hdb_response_runt_tiled = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: organism.clone(),
            organisms: vec![],
            an_likelihood: 1.0,
            provenance: Provenance::DnaRunt,
            reverse_screened: false,
            window_gap: 30,
            exempt: false,
        };
        let hdb_response_aa_tiled = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: organism.clone(),
            organisms: vec![],
            an_likelihood: 1.0,
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            window_gap: 60,
            exempt: false,
        };

        assert_eq!(
            consolidate_windows(
                // the hdb responses; (query_index, hdb_response_for_hit)
                [
                    (
                        HashId {
                            record: 0,
                            index_in_record: 1,
                            hash_type_index: 0,
                        },
                        hdb_response_hog.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 2,
                            hash_type_index: 0,
                        },
                        hdb_response_hog.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 3,
                            hash_type_index: 0,
                        },
                        hdb_response_hog.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 5,
                            hash_type_index: 0,
                        },
                        hdb_response_hog.clone()
                    ),
                    (
                        HashId {
                            record: 0,
                            index_in_record: 6,
                            hash_type_index: 0,
                        },
                        hdb_response_hog.clone()
                    ),
                    (
                        HashId {
                            record: 1,
                            index_in_record: 0,
                            hash_type_index: 1,
                        },
                        hdb_response_runt.clone()
                    ),
                    (
                        HashId {
                            record: 1,
                            index_in_record: 3,
                            hash_type_index: 1,
                        },
                        hdb_response_runt.clone()
                    ),
                    (
                        HashId {
                            record: 1,
                            index_in_record: 5,
                            hash_type_index: 1,
                        },
                        hdb_response_runt.clone()
                    ),
                    (
                        HashId {
                            record: 1,
                            index_in_record: 6,
                            hash_type_index: 1,
                        },
                        hdb_response_runt.clone()
                    ),
                    (
                        HashId {
                            record: 2,
                            index_in_record: 0,
                            hash_type_index: 2,
                        },
                        hdb_response_aa.clone()
                    ),
                    (
                        HashId {
                            record: 2,
                            index_in_record: 3,
                            hash_type_index: 2,
                        },
                        hdb_response_aa.clone()
                    ),
                    (
                        HashId {
                            record: 2,
                            index_in_record: 6,
                            hash_type_index: 2,
                        },
                        hdb_response_aa.clone()
                    ),
                    (
                        HashId {
                            record: 2,
                            index_in_record: 12,
                            hash_type_index: 2,
                        },
                        hdb_response_aa.clone()
                    ),
                    (
                        HashId {
                            record: 3,
                            index_in_record: 0,
                            hash_type_index: 3,
                        },
                        hdb_response_runt_tiled.clone()
                    ),
                    (
                        HashId {
                            record: 3,
                            index_in_record: 1,
                            hash_type_index: 3,
                        },
                        hdb_response_runt_tiled.clone()
                    ),
                    (
                        HashId {
                            record: 4,
                            index_in_record: 0,
                            hash_type_index: 2,
                        },
                        hdb_response_aa_tiled.clone()
                    ),
                    (
                        HashId {
                            record: 4,
                            index_in_record: 3,
                            hash_type_index: 2,
                        },
                        hdb_response_aa_tiled.clone()
                    ),
                    (
                        HashId {
                            record: 4,
                            index_in_record: 6,
                            hash_type_index: 2,
                        },
                        hdb_response_aa_tiled.clone()
                    ),
                ]
                .into_iter(),
                spec,
                false
            )
            .unwrap()
            .results,
            vec![
                ConsolidatedHazardResult {
                    record: 0,
                    hit_regions: vec![
                        HitRegion {
                            seq_range_start: 1,
                            seq_range_end: 45,
                            last_window_start: 3,
                            window_count: 3,
                        },
                        HitRegion {
                            seq_range_start: 5,
                            seq_range_end: 48,
                            last_window_start: 6,
                            window_count: 2,
                        },
                    ],
                    hdb_response: HdbResponse {
                        an_likelihood: 5.0,
                        ..hdb_response_hog
                    }
                },
                ConsolidatedHazardResult {
                    record: 1,
                    hit_regions: vec![
                        HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 30,
                            last_window_start: 0,
                            window_count: 1,
                        },
                        HitRegion {
                            seq_range_start: 3,
                            seq_range_end: 33,
                            last_window_start: 3,
                            window_count: 1,
                        },
                        HitRegion {
                            seq_range_start: 5,
                            seq_range_end: 36,
                            last_window_start: 6,
                            window_count: 2,
                        }
                    ],
                    hdb_response: HdbResponse {
                        an_likelihood: 4.0,
                        ..hdb_response_runt
                    }
                },
                ConsolidatedHazardResult {
                    record: 2,
                    hit_regions: vec![
                        HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 66,
                            last_window_start: 6,
                            window_count: 3,
                        },
                        HitRegion {
                            seq_range_start: 12,
                            seq_range_end: 72,
                            last_window_start: 12,
                            window_count: 1,
                        }
                    ],
                    hdb_response: HdbResponse {
                        an_likelihood: 4.0,
                        ..hdb_response_aa
                    }
                },
                ConsolidatedHazardResult {
                    record: 3,
                    hit_regions: vec![HitRegion {
                        seq_range_start: 0,
                        seq_range_end: 31,
                        last_window_start: 1,
                        window_count: 2
                    }],
                    hdb_response: HdbResponse {
                        an_likelihood: 2.0,
                        ..hdb_response_runt_tiled
                    }
                },
                ConsolidatedHazardResult {
                    record: 4,
                    hit_regions: vec![HitRegion {
                        seq_range_start: 0,
                        seq_range_end: 66,
                        last_window_start: 6,
                        window_count: 3
                    }],
                    hdb_response: HdbResponse {
                        an_likelihood: 3.0,
                        ..hdb_response_aa_tiled
                    }
                }
            ]
        );
    }
}
