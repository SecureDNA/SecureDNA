// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use certificates::{GenbankId, Sequence, SequenceIdentifier};
use doprf::{
    prf::{HashPart, Query},
    tagged::TaggedHash,
};
use hdb::{Exemptions, HdbOrganism};
use pipeline_bridge::OrganismType;
use shared_types::{
    hdb::{ConsolidatedHazardResult, HdbScreeningResult, Organism},
    synthesis_permission::SynthesisPermission,
};

pub fn mock_hazard_organism() -> Organism {
    Organism {
        name: "Mock Hazard".to_owned(),
        organism_type: OrganismType::Virus,
        ans: vec!["MH.1".to_owned()],
        tags: vec![],
    }
}

pub fn mock_hazard_cert_an_organism() -> certificates::Organism {
    certificates::Organism {
        name: "Mock Hazard".to_owned(),
        sequences: vec![SequenceIdentifier::Id(GenbankId::try_new("MH.1").unwrap())],
    }
}

pub fn mock_hazard_cert_hash_organism() -> certificates::Organism {
    certificates::Organism {
        name: "Mock Hazard".to_owned(),
        sequences: vec![SequenceIdentifier::Dna(Sequence::try_new("AAAA").unwrap())],
    }
}

pub fn mock_hazard_hdb_organism() -> HdbOrganism {
    let Organism {
        name,
        organism_type,
        ans,
        tags,
    } = mock_hazard_organism();
    HdbOrganism {
        name,
        organism_type,
        ans,
        tags,
    }
}

pub fn mock_hazard_query() -> Query {
    Query::hash_from_bytes_for_tests_only(&[100])
}

/// A dummy processing function so we don't need a real keyshare
pub fn rehash_query(query: Query) -> HashPart {
    let bytes: [u8; 32] = query.into();

    HashPart::hash_from_bytes_for_tests_only(&bytes)
}

pub fn mock_hazard_hash() -> [u8; 32] {
    rehash_query(mock_hazard_query()).into()
}

pub fn mock_el_hash() -> Exemptions {
    let hashes = vec![mock_hazard_hash()];
    Exemptions::new_unchecked(vec![], hashes.into_iter().collect())
}

fn screen_hash(hash: &TaggedHash, exemptions: &Exemptions) -> Option<ConsolidatedHazardResult> {
    if hash.hash.as_bytes() != &mock_hazard_hash() {
        return None;
    }

    let (synthesis_permission, exempt) = if exemptions.is_hash_exempt(hash.hash.as_bytes())
        || exemptions.is_organism_exempt(&mock_hazard_hdb_organism())
    {
        (SynthesisPermission::Granted, true)
    } else {
        (SynthesisPermission::Denied, false)
    };

    Some(ConsolidatedHazardResult {
        record: 0,
        hit_regions: vec![],
        synthesis_permission,
        most_likely_organism: mock_hazard_organism(),
        organisms: vec![mock_hazard_organism()],
        is_dna: true,
        is_wild_type: None,
        exempt,
    })
}

pub fn mock_screen(hashes: &[TaggedHash], exemptions: &Exemptions) -> HdbScreeningResult {
    HdbScreeningResult {
        results: hashes
            .iter()
            .filter_map(|hash| screen_hash(hash, exemptions))
            .collect(),
        debug_hdb_responses: None,
        provider_reference: None,
    }
}
