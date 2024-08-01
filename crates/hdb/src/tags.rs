// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module implements some tag-related utilities needed to transform the HDB response.

use pipeline_bridge::Tag;

use crate::{hlt::HltLookupError, HazardLookupTable, Metadata, Provenance};

/// Returns whether the metadata a) is DNA, and b) points to an HLT id_group containing
/// the `SdnaLowRiskDNA` tag.
///
/// Returns an error if the metadata's `hlt_index` or `an_subindex` are invalid (this should only
/// happen if the metadata is corrupted or a mismatched HLT / DB pair is being used)
pub fn metadata_is_low_risk_dna(
    metadata: &Metadata,
    hlt: &HazardLookupTable,
) -> Result<bool, HltLookupError> {
    if !metadata.provenance.is_dna() {
        return Ok(false);
    }

    let (_, hlt_ids) = hlt.get_with_subindex(&metadata.hlt_index, &metadata.an_subindex)?;
    Ok(hlt_ids
        .iter()
        .any(|id| id.tag() == Some(&Tag::SdnaLowRiskDNA)))
}

/// Returns whether the metadata a) is DNA, and b) points to an HLT id_group containing
/// the `SdnaLowRiskPeptide
///
/// Returns an error if the metadata's `hlt_index` or `an_subindex` are invalid (this should only
/// happen if the metadata is corrupted or a mismatched HLT / DB pair is being used)
pub fn metadata_is_low_risk_peptide(
    metadata: &Metadata,
    hlt: &HazardLookupTable,
) -> Result<bool, HltLookupError> {
    if metadata.provenance.is_dna() {
        return Ok(false);
    }

    let (_, hlt_ids) = hlt.get_with_subindex(&metadata.hlt_index, &metadata.an_subindex)?;
    Ok(hlt_ids
        .iter()
        .any(|id| id.tag() == Some(&Tag::SdnaLowRiskPeptide)))
}

/// Handles removing internal tags and either transforming or removing the
/// SdnaLowRiskDna tag. If most_likely_tags contains SdnaLowRiskDna and the
/// provenance is a DNA hit, the tag will be turned into RegulatedButPass in
/// both most_likely_tags and all the other organisms' tags, otherwise it will be
/// removed from all the other organisms' tags.
pub fn remove_or_transform_internal_tags<'a>(
    provenance: Provenance,
    most_likely_tags: &mut Vec<Tag>,
    organisms_tags: impl Iterator<Item = &'a mut Vec<Tag>>,
) {
    let hit_is_dna = provenance.is_dna();
    let mut low_risk_tag_likely = false;

    most_likely_tags.retain_mut(|tag| {
        if *tag == Tag::SdnaLowRiskDNA {
            if hit_is_dna {
                *tag = Tag::RegulatedButPass;
                low_risk_tag_likely = true;
                true
            } else {
                false
            }
        } else if *tag == Tag::SdnaLowRiskPeptide {
            if !hit_is_dna {
                *tag = Tag::RegulatedButPass;
                low_risk_tag_likely = true;
                true
            } else {
                false
            }
        } else {
            !tag.is_internal()
        }
    });

    for tags in organisms_tags {
        tags.retain_mut(|tag| {
            if *tag == Tag::SdnaLowRiskDNA || *tag == Tag::SdnaLowRiskPeptide {
                if low_risk_tag_likely {
                    // pass through, allowed
                    *tag = Tag::RegulatedButPass;
                    true
                } else {
                    // not likely or not dna, remove from all results
                    false
                }
            } else {
                !tag.is_internal()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_risk_tag_not_in_likely_not_in_possible() {
        let likely_tags = vec![Tag::HumanToHuman, Tag::ArthropodToHuman];
        let organisms_tags = vec![
            vec![Tag::HumanToHuman, Tag::ArthropodToHuman],
            vec![Tag::ArthropodToHuman, Tag::SelectAgentHhs],
        ];

        for p in [Provenance::DnaNormal, Provenance::AAWildType] {
            let mut lt = likely_tags.clone();
            let mut ot = organisms_tags.clone();
            remove_or_transform_internal_tags(p, &mut lt, ot.iter_mut());
            assert_eq!(lt, likely_tags);
            assert_eq!(ot, organisms_tags);
        }
    }

    #[test]
    fn low_risk_tag_yes_in_likely_not_in_possible() {
        let likely_tags = vec![
            Tag::HumanToHuman,
            Tag::ArthropodToHuman,
            Tag::SdnaLowRiskDNA,
        ];
        let organisms_tags = vec![
            vec![Tag::HumanToHuman, Tag::ArthropodToHuman],
            vec![Tag::ArthropodToHuman, Tag::SelectAgentHhs],
        ];

        // ILRD becomes RBP in DNA hit:
        {
            let mut lt = likely_tags.clone();
            let mut ot = organisms_tags.clone();
            remove_or_transform_internal_tags(Provenance::DnaNormal, &mut lt, ot.iter_mut());
            assert_eq!(
                lt,
                vec![
                    Tag::HumanToHuman,
                    Tag::ArthropodToHuman,
                    Tag::RegulatedButPass,
                ]
            );
            assert_eq!(ot, organisms_tags);
        }

        // ILRD gets deleted in AA hit:
        {
            let mut lt = likely_tags;
            let mut ot = organisms_tags.clone();
            remove_or_transform_internal_tags(Provenance::AAWildType, &mut lt, ot.iter_mut());
            assert_eq!(lt, vec![Tag::HumanToHuman, Tag::ArthropodToHuman]);
            assert_eq!(ot, organisms_tags);
        }
    }

    #[test]
    fn low_risk_tag_not_in_likely_yes_in_possible() {
        let likely_tags: Vec<Tag> = vec![Tag::HumanToHuman, Tag::ArthropodToHuman];
        let organisms_tags: Vec<Vec<Tag>> = vec![
            vec![
                Tag::HumanToHuman,
                Tag::ArthropodToHuman,
                Tag::SdnaLowRiskDNA,
            ],
            vec![
                Tag::ArthropodToHuman,
                Tag::SelectAgentHhs,
                Tag::SdnaLowRiskDNA,
            ],
        ];

        for p in [Provenance::DnaNormal, Provenance::AAWildType] {
            let mut lt = likely_tags.clone();
            let mut ot = organisms_tags.clone();
            remove_or_transform_internal_tags(p, &mut lt, ot.iter_mut());
            assert_eq!(lt, likely_tags);
            assert_eq!(
                ot,
                vec![
                    vec![Tag::HumanToHuman, Tag::ArthropodToHuman],
                    vec![Tag::ArthropodToHuman, Tag::SelectAgentHhs]
                ]
            );
        }
    }

    #[test]
    fn low_risk_tag_yes_in_likely_yes_in_possible() {
        let likely_tags: Vec<Tag> = vec![
            Tag::HumanToHuman,
            Tag::ArthropodToHuman,
            Tag::SdnaLowRiskDNA,
        ];
        let organisms_tags: Vec<Vec<Tag>> = vec![
            vec![
                Tag::HumanToHuman,
                Tag::ArthropodToHuman,
                Tag::SdnaLowRiskDNA,
            ],
            vec![
                Tag::ArthropodToHuman,
                Tag::SelectAgentHhs,
                Tag::SdnaLowRiskDNA,
            ],
        ];

        // ILRD becomes RBP in DNA hit, both in likely_tags and all the organisms_tags:
        {
            let mut lt = likely_tags.clone();
            let mut ot = organisms_tags.clone();
            remove_or_transform_internal_tags(Provenance::DnaNormal, &mut lt, ot.iter_mut());

            assert_eq!(
                lt,
                vec![
                    Tag::HumanToHuman,
                    Tag::ArthropodToHuman,
                    Tag::RegulatedButPass
                ]
            );
            assert_eq!(
                ot,
                vec![
                    vec![
                        Tag::HumanToHuman,
                        Tag::ArthropodToHuman,
                        Tag::RegulatedButPass
                    ],
                    vec![
                        Tag::ArthropodToHuman,
                        Tag::SelectAgentHhs,
                        Tag::RegulatedButPass
                    ]
                ]
            );
        }

        // ILRD gets deleted in AA hit, both in likely_tags and all the organisms_tags:
        {
            let mut lt = likely_tags;
            let mut ot = organisms_tags;
            remove_or_transform_internal_tags(Provenance::AAWildType, &mut lt, ot.iter_mut());
            assert_eq!(lt, vec![Tag::HumanToHuman, Tag::ArthropodToHuman]);
            assert_eq!(
                ot,
                vec![
                    vec![Tag::HumanToHuman, Tag::ArthropodToHuman],
                    vec![Tag::ArthropodToHuman, Tag::SelectAgentHhs]
                ]
            );
        }
    }
}
