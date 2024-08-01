// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use doprf::party::KeyserverId;
use serde::{Deserialize, Serialize};
use shared_types::{et::WithOtps, hdb::ConsolidatedHazardResult};

use super::{
    error::{ApiError, ApiWarning},
    DebugInfo,
};
use pipeline_bridge::{OrganismType, Tag};

/// Fields in common between the check fasta and check NCBI request types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
// tsgen
pub struct RequestCommon {
    /// Optional tag that can be included so requests from the same debugging run can be
    /// correlated in the logs.
    #[serde(default)]
    pub provider_reference: Option<String>,
    /// What region jurisdiction the request should be handled under
    pub region: Region,
    /// A list of PEM-encoded exemption token bundles, each with OTPs for
    /// the auth devices contained within, that may exempt this request from
    /// hazards.
    #[serde(default)]
    pub ets: Vec<WithOtps<String>>,
}

/// Region jurisdictions for handling requests. Controls e.g. what rules to use for setting
/// the `synthesis_permission` bit to `denied`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
// tsgen
pub enum Region {
    /// United States
    #[serde(alias = "us", alias = "US")]
    Us,
    /// European Union
    #[serde(alias = "eu", alias = "EU")]
    Eu,
    /// People's Republic of China
    #[serde(alias = "prc", alias = "PRC")]
    Prc,
    /// Check all regions. This is the default. It means:
    ///
    /// - Synthesis is granted only if the organism is safe in all regions.
    /// - Synthesis is denied if the organism is controlled in *any* region.
    #[serde(alias = "all", alias = "ALL")]
    All,
}

impl From<shared_types::synthesis_permission::Region> for Region {
    fn from(value: shared_types::synthesis_permission::Region) -> Self {
        use shared_types::synthesis_permission::Region::*;
        match value {
            Us => Self::Us,
            Eu => Self::Eu,
            Prc => Self::Prc,
            All => Self::All,
        }
    }
}

impl From<Region> for shared_types::synthesis_permission::Region {
    fn from(value: Region) -> Self {
        use shared_types::synthesis_permission::Region::*;
        match value {
            Region::Us => Us,
            Region::Eu => Eu,
            Region::Prc => Prc,
            Region::All => All,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
// tsgen
pub struct CheckFastaRequest {
    /// Well-formatted FASTA format data to check. This can be any number of records
    pub fasta: String,
    /// Common request fields
    #[serde(flatten)]
    pub common: RequestCommon,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
// tsgen
pub struct CheckNcbiRequest {
    /// NCBI ID to download the FASTA content straight from NCBI / Genbank
    pub id: String,
    /// Common request fields
    #[serde(flatten)]
    pub common: RequestCommon,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub struct ApiResponse {
    /// Whether the input was granted or denied.
    pub synthesis_permission: SynthesisPermission,
    /// If provided, the provider reference string for request tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_reference: Option<String>,
    /// Hits for each input record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hits_by_record: Vec<FastaRecordHits>,
    /// Any non-fatal warnings about the request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ApiWarning>,
    /// Any fatal errors with the request that triggered a denial.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ApiError>,
    /// Additional debug info, if requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<DebugInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// tsgen
pub enum SynthesisPermission {
    #[serde(rename = "granted")]
    Granted,
    #[serde(rename = "denied")]
    Denied,
}

impl From<shared_types::synthesis_permission::SynthesisPermission> for SynthesisPermission {
    fn from(value: shared_types::synthesis_permission::SynthesisPermission) -> Self {
        use shared_types::synthesis_permission::SynthesisPermission::*;
        match value {
            Granted => Self::Granted,
            Denied => Self::Denied,
        }
    }
}

impl From<SynthesisPermission> for shared_types::synthesis_permission::SynthesisPermission {
    fn from(value: SynthesisPermission) -> Self {
        use shared_types::synthesis_permission::SynthesisPermission::*;
        match value {
            SynthesisPermission::Granted => Granted,
            SynthesisPermission::Denied => Denied,
        }
    }
}

// Hits for one FastaRecord within a FastaFile
#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub struct FastaRecordHits {
    pub fasta_header: String,
    pub line_number_range: (u64, u64),
    pub sequence_length: u64,
    pub hits_by_hazard: Vec<HazardHits>,
}

/// An organism matched in a hit.
#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub struct HitOrganism {
    pub name: String,
    pub organism_type: OrganismType,
    pub ans: Vec<String>,
    pub tags: Vec<Tag>,
}

/// One hazard (more specifically, a specific set of hit metadata) which was screened.
///
/// Includes:
/// - metadata
/// - a list of hit regions, each of which describes which portion of the sequence matched the
/// hazard.
#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub struct HazardHits {
    #[serde(rename = "type")]
    pub sequence_type: HitType,
    /// start index of hit region
    pub is_wild_type: Option<bool>,
    pub hit_regions: Vec<HitRegion>,
    pub most_likely_organism: HitOrganism,
    pub organisms: Vec<HitOrganism>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// tsgen
pub enum HitType {
    #[serde(rename = "nuc")]
    Nuc,
    #[serde(rename = "aa")]
    AA,
}

/// Indexes marking the beginning and end of the hit region, in bp.
#[derive(Debug, Clone, Deserialize, Serialize)]
// tsgen
pub struct HitRegion {
    pub seq: String,
    pub seq_range_start: u64,
    /// index of the end of the sequence of the hit region, exclusive
    pub seq_range_end: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersionInfo {
    /// String containing synthclient cargo version & git SHA
    pub synthclient_version: String,
    /// String containing hdbserver cargo version & git SHA (None if failed to fetch)
    pub hdbserver_version: Option<String>,
    /// The HDB build timestamp (None if unknown)
    pub hdb_timestamp: Option<String>,
    /// Pairs of keyserver IDs and their version strings (keyserver cargo
    /// version & git SHA, None if failed to fetch).
    pub keyserver_versions: Option<Vec<(KeyserverId, Option<String>)>>,
}

impl HazardHits {
    pub fn from_consolidated_hazard_result(grouped: ConsolidatedHazardResult, dna: &str) -> Self {
        Self {
            hit_regions: grouped
                .hit_regions
                .into_iter()
                .map(|hit_region| HitRegion {
                    seq: dna[hit_region.seq_range_start..hit_region.seq_range_end].to_string(),
                    seq_range_start: hit_region.seq_range_start as u64,
                    seq_range_end: hit_region.seq_range_end as u64,
                })
                .collect(),
            sequence_type: if grouped.is_dna {
                HitType::Nuc
            } else {
                HitType::AA
            },
            is_wild_type: grouped.is_wild_type,
            most_likely_organism: grouped.most_likely_organism.into(),
            organisms: grouped.organisms.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use quickdna::{DnaSequence, FastaParser, Nucleotide};
    use serde_json::json;

    use crate::parsefasta::CheckFastaError;

    use super::*;

    fn parse<'de, T: Deserialize<'de>>(s: &'de str) -> T {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn check_request_notag() {
        assert_eq!(
            parse::<CheckFastaRequest>(
                r#"
                    {
                    "fasta": "hello i am dna",
                    "region": "all"
                    }
                "#
            ),
            CheckFastaRequest {
                fasta: "hello i am dna".into(),
                #[allow(deprecated)]
                common: RequestCommon {
                    region: Region::All,
                    ets: vec![],
                    provider_reference: None,
                },
            }
        )
    }

    #[test]
    fn check_request_nulltag() {
        assert_eq!(
            parse::<CheckFastaRequest>(
                r#"
                    {
                    "fasta": "hello i am dna",
                    "region": "all",
                    "provider_reference": null
                    }
                "#
            ),
            CheckFastaRequest {
                fasta: "hello i am dna".into(),
                #[allow(deprecated)]
                common: RequestCommon {
                    region: Region::All,
                    provider_reference: None,
                    ets: vec![],
                },
            }
        )
    }

    #[test]
    fn check_request_withtag() {
        assert_eq!(
            parse::<CheckFastaRequest>(
                r#"
                    {
                    "fasta": "hello i am dna",
                    "region": "all",
                    "provider_reference": "arbitrary test #5824"
                    }
                "#
            ),
            CheckFastaRequest {
                fasta: "hello i am dna".into(),
                #[allow(deprecated)]
                common: RequestCommon {
                    region: Region::All,
                    ets: vec![],
                    provider_reference: Some("arbitrary test #5824".into()),
                }
            }
        )
    }

    #[test]
    fn check_ncbi_request() {
        assert_eq!(
            parse::<CheckNcbiRequest>(
                r#"
                    {
                    "id": "FOO_78284",
                    "region": "all",
                    "provider_reference": "arbitrary test #5824"
                    }
                "#
            ),
            CheckNcbiRequest {
                id: "FOO_78284".into(),
                #[allow(deprecated)]
                common: RequestCommon {
                    region: Region::All,
                    ets: vec![],
                    provider_reference: Some("arbitrary test #5824".into()),
                }
            }
        )
    }

    #[test]
    fn synthesis_permission_granted() {
        assert_json_eq!(
            ApiResponse {
                synthesis_permission: SynthesisPermission::Granted,
                hits_by_record: vec![],
                warnings: vec![],
                errors: vec![],
                debug_info: None,
                provider_reference: None,
            },
            json!({"synthesis_permission": "granted"}),
        );
    }

    #[test]
    fn synthesis_permission_denied_complex() {
        assert_json_eq!(
            ApiResponse {
                synthesis_permission: SynthesisPermission::Denied,
                hits_by_record: vec![FastaRecordHits {
                    fasta_header: "MERS_segment_2".into(),
                    line_number_range: (24, 79),
                    sequence_length: 1234,
                    hits_by_hazard: vec![HazardHits {
                        sequence_type: HitType::Nuc,
                        is_wild_type: None,
                        hit_regions: vec![HitRegion {
                            seq: "TTGT".into(),
                            seq_range_start: 2,
                            seq_range_end: 2,
                        }],
                        most_likely_organism: HitOrganism {
                            name: "Foo".into(),
                            ans: vec!["XX_1234".into()],
                            tags: vec![Tag::HumanToHuman],
                            organism_type: OrganismType::Virus,
                        },
                        organisms: vec![
                            HitOrganism {
                                name: "Foo".into(),
                                ans: vec!["XX_1234".into()],
                                tags: vec![Tag::HumanToHuman],
                                organism_type: OrganismType::Virus,
                            },
                            HitOrganism {
                                name: "Bar".into(),
                                ans: vec!["XX_5678".into()],
                                tags: vec![Tag::ArthropodToHuman],
                                organism_type: OrganismType::Virus,
                            }
                        ],
                    }]
                }],
                warnings: vec![],
                errors: vec![],
                debug_info: None,
                provider_reference: None,
            },
            json!({
                "synthesis_permission": "denied",
                "hits_by_record": [
                    {
                        "fasta_header": "MERS_segment_2",
                        "line_number_range": [24, 79],
                        "sequence_length": 1234,
                        "hits_by_hazard": [
                            {
                                "type": "nuc",
                                "is_wild_type": null,
                                "hit_regions": [{
                                    "seq": "TTGT",
                                    "seq_range_start": 2,
                                    "seq_range_end": 2,
                                }],
                                "most_likely_organism": {
                                    "name": "Foo",
                                    "ans": ["XX_1234"],
                                    "tags": ["HumanToHuman"],
                                    "organism_type": "Virus",
                                },
                                "organisms": [
                                    {
                                        "name": "Foo",
                                        "ans": ["XX_1234"],
                                        "tags": ["HumanToHuman"],
                                        "organism_type": "Virus",
                                    },
                                    {
                                        "name": "Bar",
                                        "ans": ["XX_5678"],
                                        "tags": ["ArthropodToHuman"],
                                        "organism_type": "Virus",
                                    }
                                ]
                            }
                        ]
                    }
                ]
            })
        );
    }

    #[test]
    fn basic_warning() {
        assert_json_eq!(
            ApiResponse {
                synthesis_permission: SynthesisPermission::Granted,
                hits_by_record: vec![],
                warnings: vec![ApiWarning::exemption_certificate_expiring_soon(
                    "1970-01-01"
                )],
                errors: vec![],
                debug_info: None,
                provider_reference: Some("my_reference".to_owned()),
            },
            json!({
                "synthesis_permission": "granted",
                "warnings": [
                    {
                        "diagnostic": "certificate_expiring_soon",
                        "additional_info": "The provided exemption certificate is expiring soon, at 1970-01-01."
                    }
                ],
                "provider_reference": "my_reference"
            })
        );
    }

    #[test]
    fn error_invalid_characters() {
        let err = FastaParser::<DnaSequence<Nucleotide>>::default()
            .parse_str(
                r#"
> record1
ATCGATCGATCGATCGATCGAT
ATCGATAoopsATCGATCGATCGATCGA
        "#,
            )
            .unwrap_err();
        let err = CheckFastaError::InvalidInput(err);

        assert_json_eq!(
            ApiResponse {
                synthesis_permission: SynthesisPermission::Denied,
                hits_by_record: vec![],
                warnings: vec![],
                errors: vec![err.into()],
                debug_info: None,
                provider_reference: Some("arbitrary string".to_owned()),
            },
            json!({
                "synthesis_permission": "denied",
                "errors": [
                    {
                        "diagnostic": "invalid_input",
                        "additional_info": "Error parsing FASTA: error parsing record: bad nucleotide: 'o'",
                        "line_number_range": [4, 4]
                    }
                ],
                "provider_reference": "arbitrary string"
            })
        );
    }

    #[test]
    fn error_not_found() {
        assert_json_eq!(
            ApiResponse {
                synthesis_permission: SynthesisPermission::Denied,
                hits_by_record: vec![],
                warnings: vec![],
                errors: vec![ApiError::not_found("/foo")],
                debug_info: None,
                provider_reference: None,
            },
            json!({
                "synthesis_permission": "denied",
                "errors": [
                    {
                        "diagnostic": "not_found",
                        "additional_info": "/foo was not found."
                    }
                ]
            })
        );
    }
}
