// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use pathfinding::prelude::dfs;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;

use crate::certificate::certificate_bundle::CertificateBundle;
use crate::chain_item::ChainItem;
use crate::keypair::PublicKey;
use crate::shared_components::role::Role;
use crate::tokens::token_bundle::TokenBundle;
use crate::tokens::TokenGroup;
use crate::validation_failure::ValidationFailure;

pub type ChainItemFailure<R> = (ChainItem<R>, ValidationFailure);

/// Holds any items that failed to validate, with the reasons for failure.
/// If no items were found, then the incorrect roots may have been used.

#[derive(Debug)]
pub struct ChainValidationFailure<R: Role>(Vec<ChainItemFailure<R>>);

impl<R: Role> Display for ChainValidationFailure<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            write!(
                f,
                "Could not validate the chain but no individual items failed validation. You may be using the wrong roots.")?;
        } else {
            write!(
                f,
                "Could not validate the chain. Items that failed verification: {:?}",
                self.0
            )?;
        }
        Ok(())
    }
}

pub trait ChainTraversal {
    type R: Role;

    /// Checks for a path to the supplied issuer public key is found.
    /// If no path is found the invalid chain items will be returned, along with their reasons for failure.
    fn validate_path_to_issuers(
        &self,
        issuer_pks: &[PublicKey],
    ) -> Result<(), ChainValidationFailure<Self::R>> {
        let mut invalid_items = HashSet::new();

        for cert in self.bundle_subjects() {
            match validate_path_from_item(cert, &self.chain(), issuer_pks) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    for invalid_item in e {
                        invalid_items.insert(invalid_item);
                    }
                }
            }
        }
        Err(ChainValidationFailure(invalid_items.into_iter().collect()))
    }

    /// Returns a vec of each valid path through the chain to the supplied issuer public key.
    /// If none are found an empty vec will be returned.
    fn find_all_paths_to_issuers(&self, issuer_pks: &[PublicKey]) -> Vec<Vec<ChainItem<Self::R>>> {
        find_all_paths_to_issuers(&self.bundle_subjects(), &self.chain(), issuer_pks)
    }

    /// Returns all items which do not form part of a valid path to the issuer public key.
    /// These items may or may not be valid.
    fn find_items_not_part_of_valid_path(
        &self,
        issuer_pks: &[PublicKey],
    ) -> Vec<ChainItem<Self::R>> {
        let subjects = self.bundle_subjects();
        let chain = self.chain();

        let all_valid_certs: Vec<_> = find_all_paths_to_issuers(&subjects, &chain, issuer_pks)
            .into_iter()
            .flatten()
            .collect();

        chain
            .iter()
            .chain(subjects.iter())
            .filter(|x| !all_valid_certs.contains(x))
            .cloned()
            .collect()
    }

    /// Items included with the bundle's main certificate(s) or token in order to prove their provenance
    fn chain(&self) -> Vec<ChainItem<Self::R>>;

    /// The main certificate(s) or token which are the focus of the bundle
    fn bundle_subjects(&self) -> Vec<ChainItem<Self::R>>;
}

impl<R: Role> ChainTraversal for CertificateBundle<R> {
    type R = R;

    fn bundle_subjects(&self) -> Vec<ChainItem<Self::R>> {
        self.certs.iter().map(|c| c.clone().into()).collect()
    }

    fn chain(&self) -> Vec<ChainItem<Self::R>> {
        self.chain
            .items()
            .into_iter()
            .map(|c| c.clone().into())
            .collect()
    }
}

impl<T: TokenGroup> ChainTraversal for TokenBundle<T> {
    type R = T::AssociatedRole;

    fn chain(&self) -> Vec<ChainItem<Self::R>> {
        self.chain
            .items()
            .into_iter()
            .map(|c| c.clone().into())
            .collect()
    }

    fn bundle_subjects(&self) -> Vec<ChainItem<Self::R>> {
        vec![self.token.clone().into()]
    }
}

/// Finds first valid path from `item` to any of the provided issuer public keys
/// If a path is not found then all invalid items are returned
fn validate_path_from_item<R>(
    item: ChainItem<R>,
    chain: &[ChainItem<R>],
    issuer_pks: &[PublicKey],
) -> Result<(), Vec<ChainItemFailure<R>>>
where
    R: Role,
{
    let issuers = |c: &ChainItem<R>| {
        chain
            .iter()
            .filter(|chain_item| c.was_issued_by_item(chain_item) && chain_item.validate().is_ok())
            .cloned()
            .collect::<Vec<_>>()
    };
    let success = |c: &ChainItem<R>| issuer_pks.iter().any(|pk| c.was_issued_by_public_key(pk));

    let mut invalid_items = vec![];
    match item.validate() {
        Ok(()) => {
            if dfs(item, issuers, success).is_some() {
                return Ok(());
            };
        }
        Err(failure) => invalid_items.push((item, failure)),
    };
    for chain_item in chain {
        if let Err(err) = chain_item.validate() {
            invalid_items.push((chain_item.clone(), err))
        }
    }
    Err(invalid_items)
}

/// Finds all possible paths to issuer public keys from each item in `start_points`
fn find_all_paths_to_issuers<R: Role>(
    start_points: &[ChainItem<R>],
    chain: &[ChainItem<R>],
    issuer_pks: &[PublicKey],
) -> Vec<Vec<ChainItem<R>>> {
    let mut paths = Vec::new();
    for item in start_points {
        paths.extend(find_all_paths_to_issuers_from_item(item, chain, issuer_pks))
    }
    paths
}

fn find_all_paths_to_issuers_from_item<R>(
    item: &ChainItem<R>,
    chain: &[ChainItem<R>],
    issuer_pks: &[PublicKey],
) -> Vec<Vec<ChainItem<R>>>
where
    R: Role,
{
    if item.validate().is_err() {
        return Vec::new();
    }

    let issuers = |c: &ChainItem<R>| {
        chain
            .iter()
            .filter(|chain_item| c.was_issued_by_item(chain_item) && chain_item.validate().is_ok())
            .cloned()
            .collect()
    };
    let success = |c: &ChainItem<R>| issuer_pks.iter().any(|pk| c.was_issued_by_public_key(pk));

    let mut paths = vec![];
    let mut visited = HashSet::new();
    let mut path = vec![];

    all_dfs_paths(
        item,
        &issuers,
        &success,
        &mut visited,
        &mut path,
        &mut paths,
    );

    paths
}

fn all_dfs_paths<C, F, G>(
    start: &C,
    neighbours: &F,
    success: &G,
    visited: &mut HashSet<C>,
    path: &mut Vec<C>,
    paths: &mut Vec<Vec<C>>,
) where
    C: Eq + Hash + Clone,
    F: Fn(&C) -> Vec<C>,
    G: Fn(&C) -> bool,
{
    visited.insert(start.clone());
    path.push(start.clone());

    if success(start) {
        paths.push(path.clone());
    } else {
        for neighbor in neighbours(start) {
            if !visited.contains(&neighbor) {
                all_dfs_paths(&neighbor, neighbours, success, visited, path, paths);
            }
        }
    }
    path.pop();
    visited.remove(start);
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use crate::{
        certificate::{IssuerAdditionalFields, RequestBuilder},
        shared_components::role::Exemption,
        test_for_all_token_types,
        test_helpers::{
            create_cross_signed_intermediate_bundle, create_eltr, create_intermediate_bundle,
            create_leaf_cert, BreakableSignature,
        },
        ExemptionListTokenGroup, Expiration, KeyPair,
    };

    use super::*;

    #[test]
    fn can_traverse_from_intermediate_to_root() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let int_cert_bundle = CertificateBundle::new(intermediate_cert, None);

        int_cert_bundle
            .validate_path_to_issuers(&[*root_cert.public_key()])
            .expect("should find path to root");
    }

    #[test]
    fn can_not_traverse_from_intermediate_to_incorrect_root() {
        let kp_1 = KeyPair::new_random();
        let root_cert_1 = RequestBuilder::<Exemption>::root_v1_builder(kp_1.public_key())
            .build()
            .load_key(kp_1)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let kp_2 = KeyPair::new_random();
        let root_cert_2 = RequestBuilder::<Exemption>::root_v1_builder(kp_2.public_key())
            .build()
            .load_key(kp_2)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let intermediate_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert_1
            .issue_cert(intermediate_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let int_certificate_bundle = CertificateBundle::new(intermediate_cert, None);

        int_certificate_bundle
            .validate_path_to_issuers(&[*root_cert_2.public_key()])
            .expect_err("should not find path to root");
    }

    #[test]
    fn can_traverse_from_leaf_to_root() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .unwrap();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = intermediate_cert
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let int_certificate_bundle = CertificateBundle::new(intermediate_cert, None);

        let cert_chain = int_certificate_bundle.issue_chain();
        let leaf_certificate_bundle = CertificateBundle::new(leaf_cert, Some(cert_chain));

        leaf_certificate_bundle
            .validate_path_to_issuers(&[*root_cert.public_key()])
            .expect("should find path to root");
    }

    #[test]
    fn can_traverse_from_leaf_to_root_via_alternative_intermediate() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req_a =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();
        let int_req_b = int_req_a.clone();

        let intermediate_cert_a = root_cert
            .issue_cert(int_req_a, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .expect("Could not load key");

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        // Leaf cert issued by intermediate_cert_a
        let leaf_cert = intermediate_cert_a
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        // Consider this a reissue of intermediate_cert_a as they are derived from the same request
        let intermediate_cert_b = root_cert
            .issue_cert(int_req_b, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let int_b_cert_bundle = CertificateBundle::new(intermediate_cert_b, None);

        let cert_chain = int_b_cert_bundle.issue_chain();

        let leaf_certificate_bundle = CertificateBundle::new(leaf_cert, Some(cert_chain));
        leaf_certificate_bundle
            .validate_path_to_issuers(&[*root_cert.public_key()])
            .expect("should find path to root");
    }

    #[test]
    fn can_find_all_paths_from_leaf_to_multiple_roots() {
        let root_kp_a = KeyPair::new_random();
        let root_cert_a = RequestBuilder::<Exemption>::root_v1_builder(root_kp_a.public_key())
            .build()
            .load_key(root_kp_a)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_kp_b = KeyPair::new_random();
        let root_cert_b = RequestBuilder::<Exemption>::root_v1_builder(root_kp_b.public_key())
            .build()
            .load_key(root_kp_b)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let int_kp = KeyPair::new_random();
        let intermediate_req_a =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_req_b = intermediate_req_a.clone();

        let intermediate_cert_a = root_cert_a
            .issue_cert(intermediate_req_a, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let intermediate_cert_b = root_cert_b
            .issue_cert(intermediate_req_b, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let int_cert_bundle_a = CertificateBundle::new(intermediate_cert_a, None);
        let int_cert_bundle_b = CertificateBundle::new(intermediate_cert_b, None);

        let int_cert_bundle = int_cert_bundle_a
            .merge(int_cert_bundle_b)
            .expect("Could not merge cert bundles");

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = int_cert_bundle
            .get_lead_cert()
            .unwrap()
            .to_owned()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let chain = int_cert_bundle.issue_chain();
        let leaf_bundle = CertificateBundle::new(leaf_cert, Some(chain));

        let paths_to_root_a = leaf_bundle.find_all_paths_to_issuers(&[*root_cert_a.public_key()]);

        let paths_to_root_b = leaf_bundle.find_all_paths_to_issuers(&[*root_cert_b.public_key()]);

        let all_paths = leaf_bundle
            .find_all_paths_to_issuers(&[*root_cert_a.public_key(), *root_cert_b.public_key()]);

        assert!(paths_to_root_a.len() == 1);
        assert!(paths_to_root_b.len() == 1);
        assert!(all_paths.len() == 2)
    }

    #[test]
    fn can_find_certs_which_are_not_part_of_valid_path() {
        let root_kp_a = KeyPair::new_random();
        let root_cert_a = RequestBuilder::<Exemption>::root_v1_builder(root_kp_a.public_key())
            .build()
            .load_key(root_kp_a)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let int_kp = KeyPair::new_random();
        let intermediate_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert_a
            .issue_cert(intermediate_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let int_cert_bundle = CertificateBundle::new(intermediate_cert, None);

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = int_cert_bundle
            .get_lead_cert()
            .unwrap()
            .to_owned()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        // Create a certificate which has nothing to do with the others
        let root_kp_b = KeyPair::new_random();
        let root_cert_b = RequestBuilder::<Exemption>::root_v1_builder(root_kp_b.public_key())
            .build()
            .load_key(root_kp_b)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign")
            .into_key_unavailable();

        let mut chain = int_cert_bundle.issue_chain();
        chain.add_certificate(root_cert_b.clone());
        let leaf_bundle = CertificateBundle::new(leaf_cert, Some(chain));

        let excluded_certs =
            leaf_bundle.find_items_not_part_of_valid_path(&[*root_cert_a.public_key()]);
        assert_eq!(excluded_certs.len(), 1);
        assert_eq!(excluded_certs[0], root_cert_b.into());
    }

    #[test]
    fn intermediate_cert_with_invalid_signature_is_not_used_to_build_path() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .unwrap();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = intermediate_cert
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let mut intermediate_cert = intermediate_cert.into_key_unavailable();

        intermediate_cert.break_signature();

        let int_certificate_bundle = CertificateBundle::new(intermediate_cert.clone(), None);

        let cert_chain = int_certificate_bundle.issue_chain();
        let leaf_certificate_bundle = CertificateBundle::new(leaf_cert, Some(cert_chain));

        leaf_certificate_bundle
            .validate_path_to_issuers(&[*root_cert.public_key()])
            .expect_err("should not find path to root");

        let all_paths =
            leaf_certificate_bundle.find_all_paths_to_issuers(&[*root_cert.public_key()]);

        let excluded_certs =
            leaf_certificate_bundle.find_items_not_part_of_valid_path(&[*root_cert.public_key()]);

        assert!(all_paths.is_empty());
        assert_eq!(excluded_certs[0], intermediate_cert.into());
    }

    #[test]
    fn leaf_cert_with_invalid_signature_is_not_used_to_build_path() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .unwrap();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let mut leaf_cert = intermediate_cert
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let intermediate_cert = intermediate_cert.into_key_unavailable();

        let int_certificate_bundle = CertificateBundle::new(intermediate_cert.clone(), None);

        let cert_chain = int_certificate_bundle.issue_chain();

        leaf_cert.break_signature();
        let leaf_certificate_bundle = CertificateBundle::new(leaf_cert.clone(), Some(cert_chain));

        leaf_certificate_bundle
            .validate_path_to_issuers(&[*root_cert.public_key()])
            .expect_err("should not find path to root");

        let all_paths =
            leaf_certificate_bundle.find_all_paths_to_issuers(&[*root_cert.public_key()]);

        let excluded_certs =
            leaf_certificate_bundle.find_items_not_part_of_valid_path(&[*root_cert.public_key()]);

        println!("{:?}", excluded_certs);

        assert!(all_paths.is_empty());
        assert!(excluded_certs.contains(&leaf_cert.into()));
        assert!(excluded_certs.contains(&intermediate_cert.into()));
    }

    test_for_all_token_types!(can_traverse_from_token_to_root);
    fn can_traverse_from_token_to_root<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
    {
        let (token_bundle, root_pk) = create_token_bundle_fn();
        token_bundle
            .validate_path_to_issuers(&[root_pk])
            .expect("should find path to root");
    }

    test_for_all_token_types!(cannot_traverse_from_token_to_incorrect_root);
    fn cannot_traverse_from_token_to_incorrect_root<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
    {
        let (token_bundle, _) = create_token_bundle_fn();

        token_bundle
            .validate_path_to_issuers(&[KeyPair::new_random().public_key()])
            .expect_err("should not find path to root");
    }

    test_for_all_token_types!(cannot_traverse_to_root_with_invalid_token_signature);
    fn cannot_traverse_to_root_with_invalid_token_signature<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
    {
        let (mut token_bundle, _) = create_token_bundle_fn();
        token_bundle.token.break_signature();

        token_bundle
            .validate_path_to_issuers(&[KeyPair::new_random().public_key()])
            .expect_err("should not find path to root");
    }

    test_for_all_token_types!(can_identify_redundant_certificates);
    fn can_identify_redundant_certificates<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
        <T as TokenGroup>::AssociatedRole: Debug,
    {
        let (mut token_bundle, root_pk) = create_token_bundle_fn();

        let redundant_cert = create_leaf_cert::<T::AssociatedRole>().into_key_unavailable();
        token_bundle.chain.add_certificate(redundant_cert.clone());

        let certs_not_part_of_path = token_bundle.find_items_not_part_of_valid_path(&[root_pk]);
        assert_eq!(certs_not_part_of_path.len(), 1);
        assert_eq!(certs_not_part_of_path[0], redundant_cert.into());
    }

    #[test]
    fn cannot_find_path_to_root_from_token_with_invalid_leaf() {
        let kp = KeyPair::new_random();
        let root_pk = kp.public_key();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req = RequestBuilder::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .unwrap();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::leaf_v1_builder(leaf_kp.public_key()).build();

        let mut leaf_cert = intermediate_cert
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let int_cert_bundle = CertificateBundle::new(intermediate_cert, None);
        let chain = int_cert_bundle.issue_chain();

        leaf_cert.break_signature();
        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let token_request = create_eltr();
        let token = leaf_cert
            .load_key(leaf_kp)
            .unwrap()
            .issue_elt(token_request, Expiration::default(), vec![])
            .unwrap();
        let token_chain = leaf_bundle.issue_chain();
        let token_bundle = TokenBundle::<ExemptionListTokenGroup>::new(token, token_chain);

        token_bundle
            .validate_path_to_issuers(&[root_pk])
            .expect_err("should not find path to root");
    }

    #[test]
    fn cannot_find_path_to_root_from_token_with_invalid_intermediate() {
        let kp = KeyPair::new_random();
        let root_pk = kp.public_key();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req = RequestBuilder::intermediate_v1_builder(int_kp.public_key()).build();

        let mut intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        // break signature of intermediate cert
        intermediate_cert.break_signature();
        let int_cert_bundle = CertificateBundle::new(intermediate_cert.clone(), None);

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = intermediate_cert
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let chain = int_cert_bundle.issue_chain();

        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let token_request = create_eltr();
        let token = leaf_cert
            .load_key(leaf_kp)
            .unwrap()
            .issue_elt(token_request, Expiration::default(), vec![])
            .unwrap();
        let token_chain = leaf_bundle.issue_chain();
        let token_bundle = TokenBundle::<ExemptionListTokenGroup>::new(token, token_chain);

        token_bundle
            .validate_path_to_issuers(&[root_pk])
            .expect_err("should not find path to root");
    }

    #[test]
    fn can_identify_items_in_path_to_root_from_elt_bundle() {
        let (int_bundle, int_kp, root_pk) = create_intermediate_bundle::<Exemption>();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::leaf_v1_builder(leaf_kp.public_key()).build();

        let int_cert = int_bundle.get_lead_cert().unwrap().clone();

        let leaf_cert = int_cert
            .clone()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .unwrap();

        let chain = int_bundle.issue_chain();
        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let eltr = create_eltr();

        let elt = leaf_bundle
            .get_lead_cert()
            .unwrap()
            .clone()
            .load_key(leaf_kp)
            .unwrap()
            .issue_elt(eltr, Expiration::default(), vec![])
            .unwrap();

        let chain = leaf_bundle.issue_chain();

        let elt_bundle = TokenBundle::<ExemptionListTokenGroup>::new(elt.clone(), chain);

        let all_paths = elt_bundle.find_all_paths_to_issuers(&[root_pk]);

        // assert that only one path to issuer found
        assert_eq!(all_paths.len(), 1);

        // assert that path to issuer contains three
        assert_eq!(all_paths[0].len(), 3);

        // assert that path to issuer contains token, leaf cert and int cert
        assert!(all_paths[0].contains(&(elt.into())));
        assert!(all_paths[0].contains(&(leaf_cert.into())));
        assert!(all_paths[0].contains(&(int_cert.into())));
    }

    #[test]
    fn can_identify_certificates_in_cross_signed_path_to_root_from_elt_bundle() {
        let (int_bundle, int_kp, root_pk) = create_cross_signed_intermediate_bundle::<Exemption>();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::leaf_v1_builder(leaf_kp.public_key()).build();

        let int_cert = int_bundle.get_lead_cert().unwrap();

        let leaf_cert = int_cert
            .clone()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .unwrap();

        let chain = int_bundle.issue_chain();
        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let eltr = create_eltr();

        let elt = leaf_bundle
            .get_lead_cert()
            .unwrap()
            .clone()
            .load_key(leaf_kp)
            .unwrap()
            .issue_elt(eltr, Expiration::default(), vec![])
            .unwrap();

        let chain = leaf_bundle.issue_chain();

        let elt_bundle = TokenBundle::<ExemptionListTokenGroup>::new(elt.clone(), chain);

        let all_paths = elt_bundle.find_all_paths_to_issuers(&[root_pk]);

        // assert that two paths to issuer found
        assert_eq!(all_paths.len(), 2);

        let expected_path_1: Vec<ChainItem<Exemption>> = vec![
            elt.clone().into(),
            leaf_cert.clone().into(),
            int_bundle.certs[0].clone().into(),
        ];
        let expected_path_2: Vec<ChainItem<Exemption>> = vec![
            elt.clone().into(),
            leaf_cert.into(),
            int_bundle.certs[1].clone().into(),
        ];

        // assert that expected paths to issuer are found
        assert!(all_paths.contains(&(expected_path_1)));
        assert!(all_paths.contains(&(expected_path_2)));
    }
}
