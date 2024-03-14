// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

use pipeline_bridge::Tag;

/// Region jurisdictions for handling requests. Controls e.g. what rules to use for setting
/// the `synthesis_permission` bit to `denied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Region {
    /// United States
    Us,
    /// European Union
    Eu,
    /// People's Republic of China
    Prc,
    /// Check all regions. This is the default. It means:
    ///
    /// - Synthesis is granted only if the organism is safe in all regions.
    /// - Synthesis is denied if the organism is controlled in *any* region.
    All,
}

impl Default for Region {
    fn default() -> Self {
        Self::All
    }
}

serde_plain::derive_fromstr_from_deserialize!(Region);
serde_plain::derive_display_from_serialize!(Region);

#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash, Serialize, Deserialize)]
pub enum SynthesisPermission {
    #[serde(rename = "granted")]
    Granted,
    #[serde(rename = "denied")]
    Denied,
}

impl SynthesisPermission {
    /// Merge multiple `SynthesisPermission`s into one, returning
    /// `SynthesisPermission::Denied` if any are denials.
    ///
    /// Returns `SynthesisPermission::Granted` if the iterator is empty.
    pub fn merge<I, SP>(perms: I) -> Self
    where
        I: IntoIterator<Item = SP>,
        SP: AsRef<SynthesisPermission>,
    {
        let any_denied = perms.into_iter().any(|p| *p.as_ref() == Self::Denied);

        if any_denied {
            Self::Denied
        } else {
            Self::Granted
        }
    }
}

impl AsRef<SynthesisPermission> for SynthesisPermission {
    fn as_ref(&self) -> &SynthesisPermission {
        self
    }
}

impl From<SynthesisPermission> for &'static str {
    fn from(value: SynthesisPermission) -> Self {
        match value {
            SynthesisPermission::Granted => "granted",
            SynthesisPermission::Denied => "denied",
        }
    }
}

pub fn permission_for_region(
    tags: impl IntoIterator<Item = Tag>,
    region: Region,
) -> SynthesisPermission {
    let permission_by_tag = tags
        .into_iter()
        .map(|tag| tag_by_region_flag_table(tag, region));
    SynthesisPermission::merge(permission_by_tag)
}

pub fn tag_by_region_flag_table(tag: Tag, region: Region) -> SynthesisPermission {
    match tag {
        Tag::PotentialPandemicPathogen => SynthesisPermission::Denied,
        Tag::SelectAgentHhs => match region {
            Region::Us | Region::All => SynthesisPermission::Denied,
            Region::Prc | Region::Eu => SynthesisPermission::Granted,
        },
        Tag::SelectAgentUsda => match region {
            Region::Us | Region::All => SynthesisPermission::Denied,
            Region::Prc | Region::Eu => SynthesisPermission::Granted,
        },
        Tag::SelectAgentAphis => match region {
            Region::Us | Region::All => SynthesisPermission::Denied,
            Region::Prc | Region::Eu => SynthesisPermission::Granted,
        },
        Tag::AustraliaGroupHumanAnimalPathogen => match region {
            Region::Us | Region::Eu | Region::All => SynthesisPermission::Denied,
            Region::Prc => SynthesisPermission::Granted,
        },
        Tag::AustraliaGroupPlantPathogen => match region {
            Region::Us | Region::Eu | Region::All => SynthesisPermission::Denied,
            Region::Prc => SynthesisPermission::Granted,
        },
        Tag::PRCExportControlPart1 => match region {
            Region::Prc | Region::All => SynthesisPermission::Denied,
            Region::Us | Region::Eu => SynthesisPermission::Granted,
        },
        Tag::PRCExportControlPart2 => match region {
            Region::Prc | Region::All => SynthesisPermission::Denied,
            Region::Us | Region::Eu => SynthesisPermission::Granted,
        },
        Tag::EuropeanUnion => match region {
            Region::Eu | Region::All => SynthesisPermission::Denied,
            Region::Us | Region::Prc => SynthesisPermission::Granted,
        },
        Tag::Common
        | Tag::HumanToHuman
        | Tag::RegulatedButPass
        | Tag::SdnaLowRiskDNA
        | Tag::SdnaForceVirusReverseScreening
        | Tag::ArthropodToHuman => SynthesisPermission::Granted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that the big match statement is consistent with the human-readable table
    const TABLE: &str = r#"
    ----------------------------------------------------------------------
    - Tag                             | Us | Eu | Prc | All (no region provided)
    ----------------------------------------------------------------------
    SelectAgentHhs                    | X  | -  | -   | X
    SelectAgentUsda                   | X  | -  | -   | X
    SelectAgentAphis                  | X  | -  | -   | X
    AustraliaGroupHumanAnimalPathogen | X  | X  | -   | X
    AustraliaGroupPlantPathogen       | X  | X  | -   | X
    PRCExportControlPart1             | -  | -  | X   | X
    PRCExportControlPart2             | -  | -  | X   | X
    EuropeanUnion                     | -  | X  | -   | X
    ArthropodToHuman                  | -  | -  | -   | -
    HumanToHuman                      | -  | -  | -   | -
    PotentialPandemicPathogen         | X  | X  | X   | X
    RegulatedButPass                  | -  | -  | -   | -
    -------------------------------------------------------------
    "#;

    #[test]
    fn test_tag_table() {
        for line in TABLE.split('\n') {
            let line = line.trim();
            if line.is_empty() || line.starts_with('-') {
                continue;
            }
            let parts = line.split('|').map(|s| s.trim()).collect::<Vec<_>>();
            let [tag_name, match_us, match_eu, match_prc, match_no_region] = parts[..] else {
                panic!("bad line format: {parts:?}");
            };
            let tag: Tag = serde_json::from_str(&format!("\"{tag_name}\"")).unwrap();

            fn to_sp(s: &str) -> SynthesisPermission {
                match s {
                    "X" => SynthesisPermission::Denied,
                    "-" => SynthesisPermission::Granted,
                    other => panic!("expected X or -, got {other:?}"),
                }
            }

            assert_eq!(permission_for_region([tag], Region::Us), to_sp(match_us),);
            assert_eq!(permission_for_region([tag], Region::Eu), to_sp(match_eu),);
            assert_eq!(permission_for_region([tag], Region::Prc), to_sp(match_prc),);
            assert_eq!(
                permission_for_region([tag], Region::All),
                to_sp(match_no_region)
            );
        }
    }

    #[test]
    fn merge_empty_granted() {
        let empty: &[SynthesisPermission] = &[];
        assert_eq!(
            SynthesisPermission::merge(empty),
            SynthesisPermission::Granted
        );
    }

    #[test]
    fn merge_granted() {
        assert_eq!(
            SynthesisPermission::merge([
                SynthesisPermission::Granted,
                SynthesisPermission::Granted
            ]),
            SynthesisPermission::Granted,
        )
    }

    #[test]
    fn merge_denied() {
        assert_eq!(
            SynthesisPermission::merge([SynthesisPermission::Granted, SynthesisPermission::Denied]),
            SynthesisPermission::Denied,
        )
    }
}
