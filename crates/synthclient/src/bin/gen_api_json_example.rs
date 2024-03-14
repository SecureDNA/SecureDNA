// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small script to generate example API response for use in documentation. Comments/docs are not
//! part of the output of this script, they are managed separately.

use pipeline_bridge::{OrganismType, Tag};
use synthclient::api::*;

fn main() {
    let resp = ApiResponse {
        synthesis_permission: SynthesisPermission::Denied,
        hits_by_record: vec![FastaRecordHits {
            fasta_header: "MERS_segment_2".into(),
            line_number_range: (24, 79),
            sequence_length: 1234,
            hits_by_hazard: vec![HazardHits {
                sequence_type: HitType::Nuc,
                is_wild_type: None,
                hit_regions: vec![HitRegion {
                    seq: "CTTCATCCGCACGTGCCAGACCCTTATTCTAAGGTGGCACTT".into(),
                    seq_range_start: 0,
                    seq_range_end: 42,
                }],
                most_likely_organism: HitOrganism {
                    name: "Org 1".into(),
                    organism_type: OrganismType::Virus,
                    ans: vec!["AN.12345".into()],
                    tags: vec![Tag::HumanToHuman],
                },
                organisms: vec![
                    HitOrganism {
                        name: "Org 1".into(),
                        organism_type: OrganismType::Virus,
                        ans: vec!["AN.12345".into()],
                        tags: vec![Tag::HumanToHuman],
                    },
                    HitOrganism {
                        name: "Org 2".into(),
                        organism_type: OrganismType::Bacterium,
                        ans: vec!["AN.56789".into()],
                        tags: vec![Tag::HumanToHuman],
                    },
                ],
            }],
        }],
        warnings: vec![],
        errors: vec![],
        debug_info: None,
        provider_reference: Some("provider reference string".into()),
    };

    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
}
