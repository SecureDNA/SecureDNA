// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Crate for interfacing with the output of the pipeline.
//!
//! The pipeline produces artifacts which genhdb processes into an hdb. This create provides types
//! so that those artifacts can be easily deserialized.
//!
//! Note that these types are parallel types to those used by the pipeline aggregator to serialize
//! the artifacts. So make sure to keep the types in sync (they are similar but not identical)

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use smartstring::{LazyCompact, SmartString};

pub const PROTEIN_LEN: usize = 20;
pub const DNA_NORMAL_LEN: usize = 42;
pub const DNA_RUNT_LEN: usize = 30;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    std::hash::Hash,
    serde::Serialize,
    serde::Deserialize,
)]
// tsgen
pub enum OrganismType {
    Virus,
    Toxin,
    Bacterium,
    Fungus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HazardProperties {
    pub path_name: String,
    pub common_name: String,
    pub accessions: Vec<String>,
    pub tags: Vec<Tag>,
    // Panics if unable to deserialize
    pub organism_type: OrganismType,
    // Defaults to false (shingled)
    #[serde(default)]
    pub tiled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Provenance {
    #[serde(rename = "wild_type")]
    WildType,
    #[serde(rename = "initial_1_variant")]
    SingleReplacement,
    #[serde(rename = "initial_2_variant")]
    DoubleReplacement,
    #[serde(rename = "mh_sample")]
    MHSample,
}

/// Genhdb doesn't need any of the fields of this, just the existence
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReverseScreeningHit {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VariantEntry {
    pub variant: SmartString<LazyCompact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_likelihood: Option<f32>,
    /// If Some, this window matched in reverse screening with the given MatchedWindow
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverse_screened: Option<ReverseScreeningHit>,
    // If variant is a common seq
    pub is_common: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregatedHazard {
    /// Metadata for this hazard
    pub hazard_meta: HazardProperties,
    /// Path (relative to artifacts dir) to fraglist file (one VariantEntry per line)
    pub dna_variant_42mers_path: PathBuf,
    /// Path (relative to artifacts dir) to fraglist file (one VariantEntry per line)
    pub dna_variant_30mers_path: PathBuf,
    /// Path (relative to artifacts dir) to fraglist file (one VariantEntry per line)
    pub protein_variants_path: PathBuf,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Deserialize, Serialize,
)]
/// Tags for hazard metadata.
/// A tag may represent
/// - transmission pathway
/// - risk categorization
/// - inclusion in a controlled hazard list published by an organization
/// - internal metadata, such as whether to generate runts or how to treat organism matches
///   (these tags should still not include sensitive information, see lib.dhall)
///
///   Note: Please keep in alphabetical order, this matters for tests
// tsgen
pub enum Tag {
    /// Arthropod-to-human transmissible
    ArthropodToHuman,
    /// Australia group human animal pathogens
    /// <https://www.dfat.gov.au/publications/minisite/theaustraliagroupnet/site/en/human_animal_pathogens.html>
    AustraliaGroupHumanAnimalPathogen,
    /// Australia group plant pathogens
    /// <https://www.dfat.gov.au/publications/minisite/theaustraliagroupnet/site/en/plants.html>
    AustraliaGroupPlantPathogen,
    /// Whether the tagged sequence is a common sequence
    Common,
    /// European Union
    EuropeanUnion,
    /// Human-to-human transmissible
    HumanToHuman,
    /// Potential pandemic pathogen
    PotentialPandemicPathogen,
    /// People's Republic of China export control list (2002), parts 1 and 2
    PRCExportControlPart1,
    /// People's Republic of China export control list (2002), parts 1 and 2
    PRCExportControlPart2,
    // Generated tag; not sure if it should be in this enum (which is basically what is sent from the
    // pipelin), or if there should be a superset of this `Tag` for generated tags.
    RegulatedButPass,
    /// Internal tag: treat DNA matches from this organism specially in the HDB
    /// Intended for use with "regulatory compliance only" genomes like E. coli
    SdnaLowRiskDNA,
    /// Internal tag: normally we exempt virus wild types from reverse screening
    /// (by treating all RS matches against virus wild types as self matches),
    /// but for certain large viruses we don't want to do that. This tag turns off that
    /// behavior so the virus wild type will be reverse screened like virus variants.
    SdnaForceVirusReverseScreening,
    /// USA Select agent: US Department of Health and Human Services
    SelectAgentHhs,
    /// USA Select agent: US Department of Agriculture
    SelectAgentUsda,
    /// USA Select agent: USDA Animal and Plant Health Inspection Service
    SelectAgentAphis,
}

impl Tag {
    /// Function that returns whether a tag starts with any of the [`INTERNAL_TAG_PREFIXES`]()
    /// Internal tags won't be returned in the API response.
    /// We still shouldn't put anything extremely sensitive here, in case of HLT leakage or accidental tag return—this is more because customers don't care about these tags, not because they're dangerous to reveal. For example, we will only turn off runt generation for organisms that don't need it for security, so if the NoRuntGeneration tag leaked, it wouldn't matter.
    ///
    /// We don't check prefixes, instead we match exactly on the tag. This is because we
    /// maintain an exhaustive list of internal tags anyways.
    pub fn is_internal(&self) -> bool {
        match self {
            Tag::SdnaLowRiskDNA | Tag::SdnaForceVirusReverseScreening => true,
            Tag::ArthropodToHuman
            | Tag::AustraliaGroupHumanAnimalPathogen
            | Tag::AustraliaGroupPlantPathogen
            | Tag::Common
            | Tag::EuropeanUnion
            | Tag::HumanToHuman
            | Tag::PotentialPandemicPathogen
            | Tag::PRCExportControlPart1
            | Tag::PRCExportControlPart2
            | Tag::RegulatedButPass
            | Tag::SelectAgentHhs
            | Tag::SelectAgentUsda
            | Tag::SelectAgentAphis => false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildTrace {
    pub build_timestamp: String,
    pub pipeline_git_sha: String,
    pub pipeline_git_timestamp: String,
    pub hdb_git_sha: String,
    pub hlt_tags_modified_git_sha: Option<String>,
    pub previous_build_info: Option<Box<BuildTrace>>,
}
