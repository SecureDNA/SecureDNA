// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
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
use itertools::Itertools;
use pipeline_bridge::Tag;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::{
    hit_region::remove_multiple_regions, response::HdbOrganism, HdbResponse, HitRegion, Provenance,
};
use serde::{Deserialize, Serialize};
use shared_types::{
    hash::{HashSpec, HashTypeDescriptor},
    server_versions::HdbVersion,
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

impl ConsolidatedHazardResult {
    /// Whether this hazard's 'most likely organism' is tagged `RegulatedButPass`
    pub fn is_low_risk(&self) -> bool {
        self.hdb_response
            .most_likely_organism
            .tags
            .contains(&Tag::RegulatedButPass)
    }
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
    pub debug: Option<ConsolidationDebug>,
}

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct ConsolidationDebug {
    pub unconsolidated_responses: Vec<DebugSeqHdbResponse>,
    pub removed_overlaps: Vec<ConsolidatedHazardResult>,
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

    let mut unconsolidated_responses = vec![];

    let mut res: Vec<ConsolidatedHits> = vec![];
    for (hash_id, hdb_response) in hdb_responses {
        let htd_index = hash_id.hash_type_index as usize;
        let htdv = &hash_spec.htdv;
        let htd = htdv
            .get(htd_index)
            .ok_or(ConsolidationError::BadHashTypeIndex {
                index: htd_index,
                length: htdv.len(),
            })?;

        let seq_position = hash_id.index_in_record as usize;

        if debug {
            unconsolidated_responses.push(DebugSeqHdbResponse {
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
            let is_contiguous =
                seq_range_start <= last.hit_region.window_starts.last().unwrap() + margin;

            if htd == &last.htd
                && is_contiguous
                && hdb_response.eq_without_an_likelihood(&last.hdb_response)
                && hash_id.record == last.record
            {
                last.hit_region.window_count += 1;

                last.hit_region.window_starts.push(last_window_start);
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
                window_starts: vec![last_window_start],
                window_count: 1,
                htd_index,
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

    let mut removed = if debug { Some(vec![]) } else { None };
    let retained = remove_low_risk_overlapping_hazards(consolidated_hazard_results, &mut removed);

    Ok(Consolidation {
        results: retained,
        debug: if debug {
            Some(ConsolidationDebug {
                unconsolidated_responses,
                removed_overlaps: removed.unwrap_or_default(),
            })
        } else {
            None
        },
    })
}

/// Remove or clip hazards tagged `RegulatedButPass` whose sequences overlap with
/// hazard hits which are not tagged `RegulatedButPass`.
/// If a vec is supplied for 'removed_hazards', it will be populated with the removed hazards.
/// Note: this function will likely alter the order of the hazards.
fn remove_low_risk_overlapping_hazards(
    hazards: Vec<ConsolidatedHazardResult>,
    removed_hazards: &mut Option<Vec<ConsolidatedHazardResult>>,
) -> Vec<ConsolidatedHazardResult> {
    let (low_risk_hazards, mut high_risk_hazards): (Vec<_>, Vec<_>) =
        hazards.into_iter().partition(|hazard| hazard.is_low_risk());

    let (retained, removed): (Vec<_>, Vec<_>) = low_risk_hazards
        .into_par_iter()
        .map(|hazard| {
            let min_region_start = hazard
                .hit_regions
                .iter()
                .min_by_key(|region| region.seq_range_start)
                .map(|region| region.seq_range_start)
                .unwrap_or(0);
            let max_region_end = hazard
                .hit_regions
                .iter()
                .max_by_key(|region| region.seq_range_end)
                .map(|region| region.seq_range_end)
                .unwrap_or(usize::MAX);

            // Create an iterator of all the hit regions that may overlap with the current hazard
            let potential_overlaps = high_risk_hazards
                .iter()
                .filter(|other| other.record == hazard.record)
                .flat_map(|other| other.hit_regions.iter())
                .filter(|region| region.overlaps(min_region_start, max_region_end));

            let mut removed_regions = if removed_hazards.is_some() {
                Some(Vec::new())
            } else {
                None
            };

            let remainders = remove_multiple_regions(
                hazard.hit_regions.clone(),
                potential_overlaps,
                &mut removed_regions,
            );

            let window_len = hazard.hdb_response.provenance.window_len();
            let (updated_hit_regions, too_small): (Vec<_>, Vec<_>) = remainders
                .into_iter()
                .partition(|region| region.seq_range_end - region.seq_range_start >= window_len);

            if let Some(regions) = removed_regions.as_mut() {
                regions.extend(too_small);
            }

            if updated_hit_regions != hazard.hit_regions {
                if updated_hit_regions.is_empty() {
                    // we're removing the whole hazard
                    (None, Some(hazard))
                } else {
                    // we're modifying the hit regions
                    let removed = removed_regions.map(|removed_regions| ConsolidatedHazardResult {
                        record: hazard.record,
                        hit_regions: removed_regions,
                        hdb_response: hazard.hdb_response.clone(),
                    });

                    (
                        Some(ConsolidatedHazardResult {
                            record: hazard.record,
                            hit_regions: updated_hit_regions,
                            hdb_response: hazard.hdb_response,
                        }),
                        removed,
                    )
                }
            } else {
                // the hazard has not been modified
                (Some(hazard), None)
            }
        })
        .unzip();

    if let Some(removed_hazards) = removed_hazards {
        removed_hazards.extend(removed.into_iter().flatten());
    }

    high_risk_hazards.extend(retained.into_iter().flatten());
    high_risk_hazards
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
    pub fn to_base_hdb_screening_result(
        self,
        provider_reference: Option<String>,
        hdb_version: HdbVersion,
        timestamp: String,
    ) -> hdb_api::BaseHdbScreeningResult {
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

        let api_format_hazards: Vec<_> = self
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
                        most_likely_organism: into_organism(x.hdb_response.most_likely_organism),
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
            .sorted()
            .dedup() // DnaNormal and DnaRunt will produce duplicate entries for wild types
            .collect();

        hdb_api::BaseHdbScreeningResult {
            results: api_format_hazards,
            debug_hdb_responses: self.debug.map(|debug| {
                debug
                    .unconsolidated_responses
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
            hdb_version,
            timestamp,
        }
    }
}

/// Some unit tests for window consolidation
#[cfg(test)]
mod test {
    use std::num::NonZeroUsize;

    use pipeline_bridge::Tag;
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
                    window_starts: vec![0],
                    window_count: 1,
                    htd_index: 0,
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
                    window_starts: vec![0, 1],
                    window_count: 2,
                    htd_index: 0,
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
                        window_starts: vec![0],
                        window_count: 1,
                        htd_index: 0,
                    },
                    HitRegion {
                        seq_range_start: 2,
                        seq_range_end: 44,
                        window_starts: vec![2],
                        window_count: 1,
                        htd_index: 0,
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
                        window_starts: vec![0],
                        window_count: 1,
                        htd_index: 0,
                    },
                    HitRegion {
                        seq_range_start: 2,
                        seq_range_end: 45,
                        window_starts: vec![2, 3],
                        window_count: 2,
                        htd_index: 0,
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
                    window_starts: vec![0, 30, 60],
                    window_count: 3,
                    htd_index: 0,
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
                    window_starts: vec![0, 29, 59],
                    window_count: 3,
                    htd_index: 0,
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
                        window_starts: vec![0],
                        window_count: 1,
                        htd_index: 0,
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
                        window_starts: vec![0],
                        window_count: 1,
                        htd_index: 1,
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
                            window_starts: vec![1, 2, 3],
                            window_count: 3,
                            htd_index: 0,
                        },
                        HitRegion {
                            seq_range_start: 5,
                            seq_range_end: 48,
                            window_starts: vec![5, 6],
                            window_count: 2,
                            htd_index: 0,
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
                            window_starts: vec![0],
                            window_count: 1,
                            htd_index: 1,
                        },
                        HitRegion {
                            seq_range_start: 3,
                            seq_range_end: 33,
                            window_starts: vec![3],
                            window_count: 1,
                            htd_index: 1,
                        },
                        HitRegion {
                            seq_range_start: 5,
                            seq_range_end: 36,
                            window_starts: vec![5, 6],
                            window_count: 2,
                            htd_index: 1,
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
                            window_starts: vec![0, 3, 6],
                            window_count: 3,
                            htd_index: 2,
                        },
                        HitRegion {
                            seq_range_start: 12,
                            seq_range_end: 72,
                            window_starts: vec![12],
                            window_count: 1,
                            htd_index: 2,
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
                        window_starts: vec![0, 1],
                        window_count: 2,
                        htd_index: 3,
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
                        window_starts: vec![0, 3, 6],
                        window_count: 3,
                        htd_index: 2,
                    }],
                    hdb_response: HdbResponse {
                        an_likelihood: 3.0,
                        ..hdb_response_aa_tiled
                    }
                }
            ]
        );
    }

    #[test]
    fn test_remove_low_risk_overlapping_hazards() {
        let hazards = vec![
            ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![
                    HitRegion {
                        seq_range_start: 27,
                        seq_range_end: 109,
                        window_starts: vec![27, 30],
                        window_count: 2,
                        htd_index: 3,
                    },
                    HitRegion {
                        seq_range_start: 115,
                        seq_range_end: 157,
                        window_starts: vec![115, 120],
                        window_count: 2,
                        htd_index: 3,
                    },
                ],
                hdb_response: HdbResponse {
                    synthesis_permission: SynthesisPermission::Granted,
                    most_likely_organism: HdbOrganism {
                        name: "Bacillus anthracis".to_string(),
                        organism_type: pipeline_bridge::OrganismType::Bacterium,
                        ans: vec![
                            "NC_007322.2".to_string(),
                            "NC_007323.3".to_string(),
                            "NC_007530.2".to_string(),
                        ],
                        tags: vec![
                            Tag::AustraliaGroupHumanAnimalPathogen,
                            Tag::EuropeanUnion,
                            Tag::PRCExportControlPart2,
                            Tag::RegulatedButPass,
                            Tag::SelectAgentHhs,
                            Tag::SelectAgentUsda,
                        ],
                    },
                    organisms: vec![],
                    exempt: false,
                    an_likelihood: 1.0,
                    provenance: Provenance::DnaNormal,
                    reverse_screened: false,
                    window_gap: 30,
                },
            },
            ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![HitRegion {
                    seq_range_start: 0,
                    seq_range_end: 165,
                    window_starts: vec![0, 15],
                    window_count: 2,
                    htd_index: 4,
                }],
                hdb_response: HdbResponse {
                    synthesis_permission: SynthesisPermission::Granted,
                    most_likely_organism: HdbOrganism {
                        name: "Bacillus anthracis".to_string(),
                        organism_type: pipeline_bridge::OrganismType::Bacterium,
                        ans: vec![
                            "NC_007322.2".to_string(),
                            "NC_007323.3".to_string(),
                            "NC_007530.2".to_string(),
                        ],
                        tags: vec![
                            Tag::AustraliaGroupHumanAnimalPathogen,
                            Tag::EuropeanUnion,
                            Tag::PRCExportControlPart2,
                            Tag::SelectAgentHhs,
                            Tag::SelectAgentUsda,
                        ],
                    },
                    organisms: vec![],
                    exempt: false,
                    an_likelihood: 1.0,
                    provenance: Provenance::DnaNormal,
                    reverse_screened: false,
                    window_gap: 30,
                },
            },
        ];

        let mut removed = Some(vec![]);
        let retained = remove_low_risk_overlapping_hazards(hazards, &mut removed);

        // The low risk hazard should have been removed since it overlaps with the higher risk hazard
        assert_eq!(retained.len(), 1);
        assert!(!retained[0]
            .hdb_response
            .most_likely_organism
            .tags
            .contains(&Tag::RegulatedButPass));
        let removed_hazards = removed.unwrap();
        assert!(
            !removed_hazards.is_empty(),
            "Expected at least one removed hazard"
        );
        assert!(removed_hazards[0]
            .hdb_response
            .most_likely_organism
            .tags
            .contains(&Tag::RegulatedButPass));
    }

    #[test]
    fn test_deduplication_of_dna_normal_and_runt() {
        let make_hdb_response = |provenance| HdbResponse {
            synthesis_permission: SynthesisPermission::Granted,
            most_likely_organism: HdbOrganism {
                name: "Organism_A".into(),
                organism_type: pipeline_bridge::OrganismType::Bacterium,
                ans: vec![],
                tags: vec![],
            },
            organisms: vec![],
            exempt: false,
            an_likelihood: 1.0,
            provenance,
            reverse_screened: false,
            window_gap: 0,
        };
        let hdb_response_dna_normal = make_hdb_response(Provenance::DnaNormal);
        let hdb_response_dna_runt = make_hdb_response(Provenance::DnaRunt);

        let normal_result = ConsolidatedHazardResult {
            record: 0,
            hit_regions: vec![HitRegion {
                seq_range_start: 0,
                seq_range_end: 60,
                window_starts: vec![0, 15],
                window_count: 2,
                htd_index: 0,
            }],
            hdb_response: hdb_response_dna_normal,
        };

        let runt_result = ConsolidatedHazardResult {
            record: 0,
            hit_regions: vec![HitRegion {
                seq_range_start: 0,
                seq_range_end: 60,
                window_starts: vec![0, 15, 30],
                window_count: 3,
                htd_index: 1,
            }],
            hdb_response: hdb_response_dna_runt,
        };

        let consolidation = Consolidation {
            results: vec![normal_result, runt_result],
            debug: None,
        };

        let api_results = consolidation.to_base_hdb_screening_result(
            None,
            HdbVersion {
                server_version: "1.0.0".to_string(),
                hdb_timestamp: None,
            },
            String::new(),
        );

        // Should only have one result after deduplication
        assert_eq!(api_results.results.len(), 1);
    }
}
