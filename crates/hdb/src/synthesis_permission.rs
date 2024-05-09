// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Exemptions, HdbOrganism};
use pipeline_bridge::Tag;
use shared_types::synthesis_permission::{permission_for_region, Region, SynthesisPermission};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionResult {
    /// Whether permission was actually granted or denied.
    pub permission: SynthesisPermission,
    /// If true, this means the permission was granted, but would have been
    /// denied were it not for the provided EL.
    pub exempt: bool,
}

impl PermissionResult {
    pub fn granted() -> Self {
        Self {
            permission: SynthesisPermission::Granted,
            exempt: false,
        }
    }

    pub fn exempt() -> Self {
        Self {
            permission: SynthesisPermission::Granted,
            exempt: true,
        }
    }

    pub fn denied() -> Self {
        Self {
            permission: SynthesisPermission::Denied,
            exempt: false,
        }
    }
}

/// Calculate `synthesis_permission` based on an incomplete HDB response
pub fn get_permission<'o>(
    organisms: impl IntoIterator<Item = &'o HdbOrganism>,
    reverse_screened: bool,
    region: Region,
    exemptions: &Exemptions,
) -> PermissionResult {
    use SynthesisPermission::{Denied, Granted};

    if reverse_screened {
        return PermissionResult::granted();
    }

    let mut all_tags: Vec<Tag> = vec![];
    let mut actual_tags: Vec<Tag> = vec![];

    for organism in organisms.into_iter() {
        let exempt = exemptions.is_organism_exempt(organism);
        all_tags.extend(&organism.tags);
        if !exempt {
            actual_tags.extend(&organism.tags);
        }
    }

    let actual_permission = permission_for_region(actual_tags, region);
    let without_el = permission_for_region(all_tags, region);
    match (actual_permission, without_el) {
        (Granted, Granted) => PermissionResult::granted(),
        (Granted, Denied) => PermissionResult::exempt(),
        (Denied, _) => PermissionResult::denied(),
    }
}

#[cfg(test)]
mod tests {
    use certificates::{GenbankId, SequenceIdentifier};
    use pipeline_bridge::{OrganismType, Tag};

    use super::*;

    #[test]
    fn empty_hits_granted() {
        assert_eq!(
            get_permission(&[], false, Region::All, &Default::default()),
            PermissionResult::granted()
        );
        assert_eq!(
            get_permission(&[], true, Region::All, &Default::default()),
            PermissionResult::granted()
        );
    }

    fn make_organism(tags: &[Tag]) -> HdbOrganism {
        HdbOrganism {
            name: "Testus Unitae".into(),
            organism_type: OrganismType::Virus,
            ans: vec!["AN_1234".into()],
            tags: tags.into(),
        }
    }

    fn make_exemptions() -> Exemptions {
        crate::exemption::make_test_exemptions(vec![certificates::Organism {
            name: "Testus Unitae".into(),
            sequences: vec![SequenceIdentifier::Id(
                GenbankId::try_from("AN_1234".to_owned()).unwrap(),
            )],
        }])
    }

    #[test]
    fn some_hits_denied() {
        assert_eq!(
            get_permission(
                &[make_organism(&[Tag::SelectAgentAphis])],
                false,
                Region::All,
                &Default::default()
            ),
            PermissionResult::denied(),
        )
    }

    #[test]
    fn rs_granted() {
        assert_eq!(
            get_permission(
                &[make_organism(&[Tag::SelectAgentAphis])],
                true,
                Region::All,
                &Default::default()
            ),
            PermissionResult::granted(),
        )
    }

    #[test]
    fn benign_tag_granted() {
        assert_eq!(
            get_permission(
                &[make_organism(&[Tag::ArthropodToHuman])],
                false,
                Region::All,
                &Default::default()
            ),
            PermissionResult::granted(),
        )
    }

    #[test]
    fn diff_region_tag_granted() {
        assert_eq!(
            get_permission(
                &[make_organism(&[Tag::PRCExportControlPart1])],
                false,
                Region::Us,
                &Default::default()
            ),
            PermissionResult::granted(),
        )
    }

    #[test]
    fn same_region_tag_denied() {
        assert_eq!(
            get_permission(
                &[make_organism(&[Tag::PRCExportControlPart1])],
                false,
                Region::Prc,
                &Default::default()
            ),
            PermissionResult::denied(),
        )
    }

    #[test]
    fn exemption_granted() {
        assert_eq!(
            get_permission(
                &[make_organism(&[Tag::SelectAgentAphis])],
                false,
                Region::All,
                &make_exemptions()
            ),
            PermissionResult::exempt(),
        )
    }

    #[test]
    fn region_exemption_granted() {
        assert_eq!(
            get_permission(
                &[make_organism(&[Tag::PRCExportControlPart1])],
                false,
                Region::Prc,
                &make_exemptions()
            ),
            PermissionResult::exempt(),
        )
    }
}
