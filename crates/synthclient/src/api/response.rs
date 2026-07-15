// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use certificates::{ChainTraversal, SystemClock};
use doprf_client::{DoprfOutput, ScreeningParams};
use hdb_api::{ConsolidatedHazardResult, DebugSeqHdbResponse, HdbScreeningResult};
use itertools::Itertools;
use shared_types::metrics::SynthClientMetrics;

use crate::api::{
    ApiResponse, DebugFastaRecordHits, DebugHit, DebugInfo, FastaRecordHits, HazardHits,
};
use crate::api::{ApiWarning, VerifiableApiResponse};
use doprf_client::error::DoprfError;
use quickdna::{BaseSequence, DnaSequence, FastaRecord, NucleotideLike};
use shared_types::synthesis_permission;

/// Group the debug hit responses from the HDB by record.
fn group_debug_hits<T: NucleotideLike>(
    debug_resp: Vec<DebugSeqHdbResponse>,
    records: &[FastaRecord<DnaSequence<T>>],
) -> Result<Vec<DebugFastaRecordHits>, DoprfError> {
    let mut debug_infos: Vec<_> = records
        .iter()
        .map(|record| DebugFastaRecordHits {
            fasta_header: record.header.clone(),
            line_number_range: (record.line_range.0 as u64, record.line_range.1 as u64),
            sequence_length: record.contents.len() as u64,
            hits: vec![],
        })
        .collect();

    for hdb_response in debug_resp.into_iter() {
        let record_index =
            usize::try_from(hdb_response.record).map_err(|_| DoprfError::InvalidRecord)?;
        let record = records.get(record_index).ok_or(DoprfError::InvalidRecord)?;
        let debug_info = debug_infos
            .get_mut(record_index)
            .ok_or(DoprfError::InvalidRecord)?;

        let dna = record.contents.to_string();
        let hit = DebugHit::from_hdb_response(hdb_response, &dna);
        debug_info.hits.push(hit);
    }

    Ok(debug_infos)
}

/// Group the consolidated hit responses from the HDB by record.
fn group_hits<T: NucleotideLike>(
    consolidated_hazard_results: Vec<ConsolidatedHazardResult>,
    records: &[FastaRecord<DnaSequence<T>>],
) -> Result<Vec<FastaRecordHits>, DoprfError> {
    let mut hits_by_record: Vec<_> = records
        .iter()
        .map(|record| FastaRecordHits {
            fasta_header: record.header.clone(),
            line_number_range: (record.line_range.0 as u64, record.line_range.1 as u64),
            sequence_length: record.contents.len() as u64,
            hits_by_hazard: vec![],
        })
        .collect();

    for grouped in consolidated_hazard_results {
        let record_index =
            usize::try_from(grouped.record).map_err(|_| DoprfError::InvalidRecord)?;
        let record = records.get(record_index).ok_or(DoprfError::InvalidRecord)?;
        let fasta_record_hits = hits_by_record
            .get_mut(record_index)
            .ok_or(DoprfError::InvalidRecord)?;

        let dna = record.contents.to_string();
        let hit = HazardHits::from_consolidated_hazard_result(grouped, &dna);
        fasta_record_hits.hits_by_hazard.push(hit);
    }

    hits_by_record.retain(|fasta_record_hits| !fasta_record_hits.hits_by_hazard.is_empty());

    Ok(hits_by_record)
}

impl ApiResponse {
    pub fn from_doprf_output<T: NucleotideLike>(
        output: DoprfOutput,
        records: &[FastaRecord<DnaSequence<T>>],
        metrics: &Option<Arc<SynthClientMetrics>>,
        params: &ScreeningParams,
        provider_reference: Option<String>,
    ) -> Result<Self, DoprfError> {
        let base_response = output.response.base;
        let verifiable = output.response.verification.map(|v| VerifiableApiResponse {
            synthclient_version: v.synthclient_version,
            response_json: v.result_json,
            signature: v.signature,
            public_key: v.public_key,
            history: v.history,
            sha3_256: v.sha3_256,
        });

        let synthesis_permission = synthesis_permission::SynthesisPermission::merge(
            base_response.results.iter().map(|h| h.synthesis_permission),
        );

        let debug_grouped_hits = base_response
            .debug_hdb_responses
            .map(|debug_resp| group_debug_hits(debug_resp, records))
            .transpose()?;

        let hits_by_record = group_hits(base_response.results, records)?;

        if let Some(m) = &metrics {
            m.hash_counter.inc_by(output.n_hashes);
            let total_bp = records.iter().fold(0u64, |total, record| {
                total.saturating_add(record.contents.len().try_into().unwrap_or(u64::MAX))
            });
            m.bp_counter.inc_by(total_bp);
        }

        use synthesis_permission::SynthesisPermission::Granted;
        let dummies: u64 = records.len().try_into().unwrap_or(u64::MAX);
        let mut warnings = match synthesis_permission {
            Granted if output.too_short => vec![ApiWarning::too_short()],
            Granted if output.n_hashes <= dummies => vec![ApiWarning::too_ambiguous()],
            _ => vec![],
        };

        // Warn about soon to expire exemption tokens and certificates in their chain
        warnings.extend(
            params
                .ets
                .iter()
                .flat_map(|et| {
                    et.et
                        .expiry_within_days_excluding_shorter_validity(30, &SystemClock)
                })
                .unique()
                .map(ApiWarning::certificate_expiring_soon),
        );

        // Warn about soon to expire synth tokens and certificates in their chain
        warnings.extend(
            params
                .certs
                .token
                .expiry_within_days_excluding_shorter_validity(30, &SystemClock)
                .into_iter()
                .map(ApiWarning::certificate_expiring_soon),
        );

        if let Some(m) = &metrics {
            m.hazards.inc_by(hits_by_record.len() as u64);
        }

        Ok(ApiResponse {
            synthesis_permission: synthesis_permission.into(),
            hits_by_record,
            verifiable,

            warnings,
            errors: vec![],
            debug_info: params.include_debug_info.then_some(DebugInfo {
                grouped_hits: debug_grouped_hits.unwrap_or_default(),
            }),
            provider_reference,
        })
    }

    pub fn from_hdb_result<T: NucleotideLike>(
        result: HdbScreeningResult,
        records: &[FastaRecord<DnaSequence<T>>],
        params: &ScreeningParams,
        provider_reference: Option<String>,
    ) -> Result<Self, DoprfError> {
        Self::from_doprf_output(
            DoprfOutput {
                n_hashes: records.len() as u64 + 1,
                too_short: false,
                response: result,
            },
            records,
            &None,
            params,
            provider_reference,
        )
    }
}

#[cfg(test)]
mod tests {
    use doprf_client::{DoprfOutput, ScreeningParams};
    use hdb_api::BaseHdbScreeningResult;
    use pipeline_bridge::OrganismType;
    use quickdna::{DnaSequence, FastaRecord, NucleotideAmbiguous};
    use scep_client_helpers::ClientCerts;
    use securedna_versioning::version::get_version;
    use sha3::{Digest, Sha3_256};
    use shared_types::{server_versions::HdbVersion, synthesis_permission::SynthesisPermission};
    use std::{str::FromStr, sync::Arc};

    use crate::api::{
        ApiResponse, DebugFastaRecordHits, DebugHit, DebugInfo, FastaRecordHits, HazardHits,
    };

    #[test]
    fn test_create_api_response() {
        let t_integrationitis = hdb_api::Organism {
            name: "T. Integrationitis".to_owned(),
            organism_type: OrganismType::Virus,
            ans: vec!["TST_00000".to_owned()],
            tags: vec![
                pipeline_bridge::Tag::PRCExportControlPart1,
                pipeline_bridge::Tag::SelectAgentAphis,
            ],
        };

        let hdb_screening_result = BaseHdbScreeningResult {
            results: vec![hdb_api::ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![hdb_api::HitRegion {
                    seq_range_start: 0,
                    seq_range_end: 42,
                }],
                synthesis_permission: SynthesisPermission::Denied,
                most_likely_organism: t_integrationitis.clone(),
                organisms: vec![t_integrationitis.clone()],
                is_dna: true,
                is_wild_type: None,
                exempt: false,
            }],
            debug_hdb_responses: Some(vec![hdb_api::DebugSeqHdbResponse {
                record: 0,
                seq_range_start: 0,
                seq_range_end: 42,
                synthesis_permission: SynthesisPermission::Denied,
                most_likely_organism: t_integrationitis.clone(),
                organisms: vec![t_integrationitis.clone()],
                an_likelihood: -0.1,
                provenance: hdb_api::Provenance::DnaNormal,
                reverse_screened: false,
                window_gap: 1,
                exempt: false,
            }]),
            provider_reference: Some("provider_reference".to_owned()),
            timestamp: "2024-05-29T12:00:00Z".to_string(),
            hdb_version: HdbVersion {
                server_version: "foo".to_owned(),
                hdb_timestamp: None,
            },
        };

        let output = DoprfOutput {
            n_hashes: 5,
            too_short: false,
            response: hdb_api::HdbScreeningResult::base(hdb_screening_result),
        };

        let records: Vec<FastaRecord<DnaSequence<NucleotideAmbiguous>>> = vec![FastaRecord {
            header: "testheader".to_owned(),
            contents: DnaSequence::from_str(&"C".repeat(46)).unwrap(),
            line_range: (1, 2),
        }];

        let fasta_sha3_256_hex = hex::encode(
            Sha3_256::new()
                .chain_update(
                    r#"{"fasta":">testheader\nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}"#,
                )
                .finalize(),
        );

        let params = ScreeningParams {
            certs: Arc::new(ClientCerts::load_test_certs()),
            include_debug_info: true,
            verifiable_screening: false,
            region: shared_types::synthesis_permission::RawRegion::ALL,
            ets: vec![],
            fasta_sha3_256_hex,
            synthclient_version: get_version(),
        };

        let api_response = ApiResponse::from_doprf_output(
            output,
            &records,
            &None,
            &params,
            Some("provider_reference".to_owned()),
        );

        assert_eq!(
            api_response.ok(),
            Some(ApiResponse {
                synthesis_permission: crate::api::SynthesisPermission::Denied,
                provider_reference: Some("provider_reference".to_owned()),
                hits_by_record: vec![FastaRecordHits {
                    fasta_header: "testheader".to_owned(),
                    line_number_range: (1, 2),
                    sequence_length: 46,
                    hits_by_hazard: vec![HazardHits {
                        sequence_type: crate::api::HitType::Nuc,
                        is_wild_type: None,
                        hit_regions: vec![crate::api::HitRegion {
                            seq: "C".repeat(42),
                            seq_range_start: 0,
                            seq_range_end: 42
                        }],
                        most_likely_organism: t_integrationitis.clone().into(),
                        organisms: vec![t_integrationitis.clone().into()],
                    }],
                }],
                verifiable: None,
                warnings: vec![],
                errors: vec![],
                debug_info: Some(DebugInfo {
                    grouped_hits: vec![DebugFastaRecordHits {
                        fasta_header: "testheader".to_owned(),
                        line_number_range: (1, 2),
                        sequence_length: 46,
                        hits: vec![DebugHit {
                            seq: "C".repeat(42),
                            index: 0,
                            most_likely_organism: t_integrationitis.clone().into(),
                            organisms: vec![t_integrationitis.clone().into()],
                            an_likelihood: -0.1,
                            provenance: crate::api::SequenceProvenance::DnaNormal,
                            reverse_screened: false,
                            window_gap: 1,
                        }]
                    }]
                }),
            })
        );
    }
}
