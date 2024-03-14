// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashSet;

use crate::{database::EntryHash, HdbOrganism};
use certificates::{ExemptionListTokenGroup, SequenceIdentifier, TokenBundle};

#[derive(Default, Debug)]
pub struct Exemptions {
    token_bundles: Vec<TokenBundle<ExemptionListTokenGroup>>,
    hashes: HashSet<EntryHash>,
}

impl Exemptions {
    pub fn new_unchecked(
        token_bundles: Vec<TokenBundle<ExemptionListTokenGroup>>,
        hashes: HashSet<EntryHash>,
    ) -> Self {
        Exemptions {
            token_bundles,
            hashes,
        }
    }

    pub fn is_hash_exempt(&self, hash: &EntryHash) -> bool {
        self.hashes.contains(hash)
    }

    pub fn is_organism_exempt(&self, hdb_organism: &HdbOrganism) -> bool {
        let mut not_covered: HashSet<&String> = hdb_organism.ans.iter().collect();

        for token_bundle in &self.token_bundles {
            for organism in token_bundle.token.exemptions() {
                if organism.name == hdb_organism.name {
                    return true;
                }
                for sequence in &organism.sequences {
                    if let SequenceIdentifier::Id(id) = sequence {
                        not_covered.remove(&id.to_string());
                    }
                }
            }
        }
        not_covered.is_empty()
    }
}

#[cfg(test)]
pub fn make_exemptions(organisms: Vec<certificates::Organism>) -> Exemptions {
    use certificates::{
        test_helpers::create_leaf_cert, CertificateBundle, Description, Exemption,
        ExemptionListTokenRequest, Expiration,
    };
    let requestor = Description::default()
        .with_name("some researcher")
        .with_email("email@example.com");

    let shipping_address = vec!["19 Some Street".to_string(), "Some City".to_string()];

    let eltr = ExemptionListTokenRequest::v1_token_request(
        organisms,
        requestor,
        vec![],
        vec![shipping_address],
    );

    let leaf_cert = create_leaf_cert::<Exemption>();

    let issuer_auth_devices = Vec::new();

    let token = leaf_cert
        .issue_elt(
            eltr,
            Expiration::expiring_in_days(90).unwrap(),
            issuer_auth_devices,
        )
        .unwrap();

    let leaf_cert_bundle = CertificateBundle::new(leaf_cert, None);
    let chain = leaf_cert_bundle.issue_chain();
    let token_bundle = TokenBundle { token, chain };

    Exemptions {
        token_bundles: vec![token_bundle],
        hashes: HashSet::new(),
    }
}

#[cfg(test)]
mod test {
    use certificates::{GenbankId, Organism};

    use super::*;

    #[test]
    fn test_is_exempt() {
        let test_organism = HdbOrganism {
            name: "Test organism".to_owned(),
            organism_type: pipeline_bridge::OrganismType::Bacterium,
            ans: vec!["A001".to_owned(), "A002".to_owned()],
            tags: vec![],
        };

        let a001 = SequenceIdentifier::Id(GenbankId::try_new("A001".to_owned()).unwrap());
        let a002 = SequenceIdentifier::Id(GenbankId::try_new("A002".to_owned()).unwrap());
        let a003 = SequenceIdentifier::Id(GenbankId::try_new("A003".to_owned()).unwrap());

        let irrelevant = Organism {
            name: "Non-matching name".to_owned(),
            sequences: vec![SequenceIdentifier::Id(
                GenbankId::try_new("B001".to_owned()).unwrap(),
            )],
        };
        let no_cover = Organism {
            name: "Non-matching name".to_owned(),
            sequences: vec![a001.clone(), a003.clone()],
        };
        let exact = Organism {
            name: "Non-matching name".to_owned(),
            sequences: vec![a001.clone(), a002.clone()],
        };
        let superfluous = Organism {
            name: "Non-matching name".to_owned(),
            sequences: vec![a001.clone(), a002.clone(), a003.clone()],
        };
        let by_name = Organism {
            name: "Test organism".to_owned(),
            sequences: vec![a001.clone(), a003.clone()],
        };

        // These ELs *don't* cover the organism:
        assert!(!make_exemptions(vec![irrelevant.clone()]).is_organism_exempt(&test_organism));
        assert!(!make_exemptions(vec![no_cover]).is_organism_exempt(&test_organism));

        // This one covers the organism exactly:
        assert!(make_exemptions(vec![exact.clone()]).is_organism_exempt(&test_organism));

        // This one contains superfluous ANs, but covers the organism:
        assert!(make_exemptions(vec![superfluous]).is_organism_exempt(&test_organism));

        // It suffices for any entry of the EL to cover the organism:
        assert!(make_exemptions(vec![exact, irrelevant]).is_organism_exempt(&test_organism));

        // Here the ANs don't quite match, but the organism name matches exactly:
        assert!(make_exemptions(vec![by_name]).is_organism_exempt(&test_organism));
    }
}
