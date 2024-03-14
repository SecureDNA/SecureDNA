// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

use pipeline_bridge::{OrganismType, Tag};
use shared_types::synthesis_permission::{Region, SynthesisPermission};

use crate::{
    hlt::HLTLookupError, synthesis_permission::PermissionResult, tags, Exemptions, HLTId,
    HazardLookupTable, Metadata, Provenance,
};

/// Note: if modifying this structure, make sure to also modify Hash impl!
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HdbResponse {
    pub synthesis_permission: SynthesisPermission,
    pub most_likely_organism: HdbOrganism,
    pub organisms: Vec<HdbOrganism>,
    pub an_likelihood: f32,
    pub provenance: Provenance,
    pub reverse_screened: bool,
    pub window_gap: usize,
    pub exempt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct HdbOrganism {
    pub name: String,
    pub organism_type: OrganismType,
    pub ans: Vec<String>,
    pub tags: Vec<Tag>,
}

impl HdbResponse {
    /// For comparisons w/out an_likelihood, which allows us to sum an_likelihood during
    /// consolidation
    pub fn eq_without_an_likelihood(&self, other: &Self) -> bool {
        self.synthesis_permission == other.synthesis_permission
            && self.most_likely_organism == other.most_likely_organism
            && self.organisms == other.organisms
            && self.provenance == other.provenance
            && self.reverse_screened == other.reverse_screened
            && self.window_gap == other.window_gap
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HdbResponseError {
    #[error("metadata hlt index {0} missing in provided HLT")]
    MissingMetaHLTIndex(u32),
    #[error("metadata an subindex {1} missing in provided HLT entry {0}")]
    MissingMetaANSubindex(u32, u8),
}

impl HdbOrganism {
    pub fn from_ids(
        ids: &[HLTId],
        hlt_index: u32,
        an_subindex: u8,
    ) -> Result<Self, HLTLookupError> {
        let mut name: Option<String> = None;
        let mut organism_type: Option<OrganismType> = None;
        let mut ans = vec![];
        let mut tags = vec![];

        for id in ids {
            match id {
                HLTId::OrganismName(s) => name = Some(s.clone()),
                HLTId::Accession(an) => ans.push(an.clone()),
                HLTId::Tag(tag) => tags.push(*tag),
                HLTId::Tiled => {}
                HLTId::OrganismType(t) => organism_type = Some(*t),
            }
        }

        let name = name.ok_or(HLTLookupError::MissingOrganismName(hlt_index, an_subindex))?;
        let organism_type =
            organism_type.ok_or(HLTLookupError::MissingOrganismType(hlt_index, an_subindex))?;
        ans.sort();
        ans.dedup();
        tags.sort();
        tags.dedup();
        Ok(HdbOrganism {
            name,
            organism_type,
            ans,
            tags,
        })
    }
}

impl HdbResponse {
    pub fn with_hlt(
        metadata: Metadata,
        region: Region,
        exemptions: &Exemptions,
        hlt: &HazardLookupTable,
    ) -> Result<Self, HLTLookupError> {
        let (hlt_entry, likely_hltids) =
            hlt.get_with_subindex(&metadata.hlt_index, &metadata.an_subindex)?;

        let mut organisms: Vec<HdbOrganism> = hlt_entry
            .iter()
            .map(|ids| HdbOrganism::from_ids(ids.1, metadata.hlt_index, metadata.an_subindex))
            .collect::<Result<_, _>>()?;
        let mut most_likely_organism =
            HdbOrganism::from_ids(likely_hltids, metadata.hlt_index, metadata.an_subindex)?;

        tags::remove_or_transform_internal_tags(
            metadata.provenance,
            &mut most_likely_organism.tags,
            organisms.iter_mut().map(|organism| &mut organism.tags),
        );
        if metadata.is_common {
            most_likely_organism.tags.push(Tag::Common);
            for organism in organisms.iter_mut() {
                organism.tags.push(Tag::Common);
            }
        }

        let an_likelihood: f32 = metadata.an_likelihood.into();
        assert!(!an_likelihood.is_nan());

        // It's unlikely that we'll cross major taxonomic boundaries, so we'd expect that if one
        // hazard is tiled, then all hazards should be tiled (same for hazard_type)
        let tiled = likely_hltids.iter().any(HLTId::tiled);
        let window_gap = metadata.provenance.window_gap(tiled);

        let PermissionResult { permission, exempt } = crate::synthesis_permission::get_permission(
            &organisms,
            metadata.reverse_screened,
            region,
            exemptions,
        );

        Ok(Self {
            synthesis_permission: permission,
            most_likely_organism,
            organisms,
            an_likelihood,
            provenance: metadata.provenance,
            reverse_screened: metadata.reverse_screened,
            window_gap,
            exempt,
        })
    }
}

#[cfg(test)]
mod tests {
    use certificates::{GenbankId, Organism, SequenceIdentifier};

    use crate::exemption::make_exemptions;

    use super::*;

    static COMPLICATED_HLT: &str = r#"
    {
        "entries": {
            "0": { "id_groups": [
                [
                    {"OrganismName": "Nastyitis"},
                    {"OrganismType": "Virus"},
                    {"Accession": "NC_00000.0"},
                    {"Accession": "NC_00000.1"},
                    {"Tag": "HumanToHuman"},
                    {"Tag": "SdnaLowRiskDNA"}
                ],
                [
                    {"OrganismName": "Nastyitis variant"},
                    {"OrganismType": "Virus"},
                    {"Accession": "NC_00001"},
                    {"Tag": "HumanToHuman"},
                    {"Tag": "ArthropodToHuman"},
                    {"Tag": "SdnaLowRiskDNA"}
                ]
            ] },
            "198": { "id_groups": [
                [
                    {"OrganismName": "Nastytoxin"},
                    {"OrganismType": "Toxin"},
                    {"Accession": "NC_00002"},
                    {"Tag": "SelectAgentHhs"},
                    {"Tag": "SdnaLowRiskDNA"}
                ]
            ] }
        }
    }
    "#;

    #[test]
    pub fn generates_correct_response_single_subentry() {
        let hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();
        let metadata = Metadata {
            hlt_index: 198,
            an_subindex: 0,
            an_likelihood: half::f16::from_f32(0.5),
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            is_common: false,
        };

        insta::assert_yaml_snapshot!(HdbResponse::with_hlt(
            metadata,
            Region::Us,
            &Default::default(),
            &hlt
        )
        .unwrap())
    }

    #[test]
    pub fn generates_correct_response_multiple_subentry() {
        let hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();
        let metadata = Metadata {
            hlt_index: 0,
            an_subindex: 0,
            an_likelihood: half::f16::from_f32(0.5),
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            is_common: false,
        };

        insta::assert_yaml_snapshot!(HdbResponse::with_hlt(
            metadata,
            Region::Us,
            &Default::default(),
            &hlt
        )
        .unwrap())
    }

    #[test]
    pub fn generates_correct_response_multiple_subentry_organism_not_likely() {
        let hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();
        let metadata = Metadata {
            hlt_index: 0,
            an_subindex: 1,
            an_likelihood: half::f16::from_f32(0.5),
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            is_common: false,
        };
        insta::assert_yaml_snapshot!(HdbResponse::with_hlt(
            metadata,
            Region::Us,
            &Default::default(),
            &hlt
        )
        .unwrap())
    }

    #[test]
    pub fn generates_correct_response_exemption() {
        let hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();
        let metadata = Metadata {
            hlt_index: 198,
            an_subindex: 0,
            an_likelihood: half::f16::from_f32(0.5),
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            is_common: false,
        };

        let exemption = Organism {
            name: "Nastytoxin".into(),
            sequences: vec![SequenceIdentifier::Id(
                GenbankId::try_from("NC_00002".to_owned()).unwrap(),
            )],
        };

        insta::assert_yaml_snapshot!(HdbResponse::with_hlt(
            metadata,
            Region::Us,
            &make_exemptions(vec![exemption]),
            &hlt
        )
        .unwrap())
    }

    #[test]
    pub fn generates_correct_response_insufficient_exemption() {
        let hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();
        let metadata = Metadata {
            hlt_index: 198,
            an_subindex: 0,
            an_likelihood: half::f16::from_f32(0.5),
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            is_common: false,
        };

        let exemption = Organism {
            name: "Othertoxin".into(),
            sequences: vec![SequenceIdentifier::Id(
                GenbankId::try_from("NC_00003".to_owned()).unwrap(),
            )],
        };

        insta::assert_yaml_snapshot!(HdbResponse::with_hlt(
            metadata,
            Region::Us,
            &make_exemptions(vec![exemption]),
            &hlt
        )
        .unwrap())
    }

    #[test]
    fn removes_low_risk_tag() {
        let hlt: HazardLookupTable = serde_json::from_str(
            r#"{ "entries": {
            "0": { "id_groups": [
                [{"OrganismName": "Test"}, {"OrganismType": "Virus"}, {"Tag": "HumanToHuman"}],
                [{"OrganismName": "Test"}, {"OrganismType": "Virus"}, {"Tag": "SdnaLowRiskDNA"}]
            ] }
        } }"#,
        )
        .unwrap();

        fn run_tags(
            hlt_index: u32,
            an_subindex: u8,
            hlt: &HazardLookupTable,
        ) -> (Vec<Tag>, Vec<Tag>) {
            let metadata = Metadata {
                hlt_index,
                an_subindex,
                an_likelihood: half::f16::from_f32(0.),
                provenance: Provenance::DnaNormal,
                reverse_screened: false,
                is_common: false,
            };

            let resp =
                HdbResponse::with_hlt(metadata, Region::All, &Default::default(), hlt).unwrap();
            let mut possible_tags: Vec<Tag> = resp
                .organisms
                .into_iter()
                .flat_map(|o| o.tags.into_iter())
                .collect();
            possible_tags.sort();
            possible_tags.dedup();
            (resp.most_likely_organism.tags, possible_tags)
        }

        assert_eq!(
            run_tags(0, 0, &hlt),
            (vec![Tag::HumanToHuman], vec![Tag::HumanToHuman],)
        );

        assert_eq!(
            run_tags(0, 1, &hlt),
            (
                vec![Tag::RegulatedButPass],
                vec![Tag::HumanToHuman, Tag::RegulatedButPass],
            )
        );
    }

    #[test]
    fn common_tag() {
        fn run_with_common(is_common: bool) -> (Vec<Tag>, Vec<Tag>) {
            let hlt: HazardLookupTable = serde_json::from_str(
                r#"{ "entries": {
                "0": { "id_groups": [
                    [{"OrganismName": "Test"}, {"OrganismType": "Virus"}]
                ] }
            } }"#,
            )
            .unwrap();

            let metadata = Metadata {
                hlt_index: 0,
                an_subindex: 0,
                an_likelihood: half::f16::from_f32(0.),
                provenance: Provenance::DnaNormal,
                reverse_screened: false,
                is_common, // the value we're checking is propagated into tags
            };

            let resp =
                HdbResponse::with_hlt(metadata, Region::All, &Default::default(), &hlt).unwrap();
            let mut possible_tags: Vec<Tag> = resp
                .organisms
                .into_iter()
                .flat_map(|o| o.tags.into_iter())
                .collect();
            possible_tags.sort();
            possible_tags.dedup();

            (resp.most_likely_organism.tags, possible_tags)
        }

        assert_eq!(
            run_with_common(true),
            (vec![Tag::Common], vec![Tag::Common])
        );
        assert_eq!(run_with_common(false), (vec![], vec![]));
    }
}
