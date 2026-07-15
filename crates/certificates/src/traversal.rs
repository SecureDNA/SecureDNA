// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use thiserror::Error;
use time::Duration;

use crate::chain::Chain;
use crate::chain_item::{ChainItem, ChainItemValidationError};
use crate::key::signing::PublicKey;
use crate::revocation::RevocationList;
use crate::shared_components::role::Role;
use crate::{ChainItemDigest, Clock, Digestible, HierarchyKind};

type ValidPath<R> = Vec<ChainItem<R>>;

const TRAVERSAL_LIMIT: usize = 20;

pub fn traversal_limit_message() -> String {
    format!(
        "the chain traversal limit of {} items was reached without finding a valid path",
        TRAVERSAL_LIMIT
    )
}

/// Holds any items that failed to validate, with the reasons for failure.
/// If no items were found, then the incorrect roots may have been used.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum ChainValidationError<R: Role> {
    InvalidItems(Vec<ChainItemValidationError<R>>),
    TraversalLimitReached,
}

impl<R: Role> ChainValidationError<R> {
    pub fn invalid_items(mut invalid_items: Vec<ChainItemValidationError<R>>) -> Self {
        invalid_items.sort_by(|a, b| a.item.cmp(&b.item));
        Self::InvalidItems(invalid_items)
    }

    // For use in server error messages
    pub fn user_friendly_text(&self) -> String {
        match self {
            Self::InvalidItems(invalid_items) => invalid_items
                .iter()
                .map(|ChainItemValidationError { item, error }| {
                    format!(
                        "the {} is not valid due to {}",
                        item.user_friendly_text(),
                        error.user_friendly_text()
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
            Self::TraversalLimitReached => traversal_limit_message(),
        }
    }

    #[cfg(test)]
    pub fn expect_invalid_items(self) -> Vec<ChainItemValidationError<R>> {
        match self {
            ChainValidationError::InvalidItems(invalid_items) => invalid_items,
            ChainValidationError::TraversalLimitReached => {
                panic!("Expected invalid items, but got traversal limit reached")
            }
        }
    }
}

// For use in CLI tooling
impl<R: Role> Display for ChainValidationError<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidItems(invalid_items) => {
                let mut items_iter = invalid_items.iter().peekable();
                while let Some(item) = items_iter.next() {
                    write!(f, "{}", item)?;
                    if items_iter.peek().is_some() {
                        writeln!(f, "\n")?;
                    }
                }
            }
            Self::TraversalLimitReached => writeln!(f, "{}", traversal_limit_message())?,
        }
        Ok(())
    }
}

pub trait ChainTraversal {
    type R: Role;

    /// Checks that a path to the supplied issuer public key(s) is found.
    /// If no path is found the invalid chain items will be returned, along with their reasons for failure.
    fn validate_path_to_issuers(
        &self,
        issuer_pks: &[PublicKey],
        list: Option<&RevocationList>,
        clock: &impl Clock,
    ) -> Result<(), ChainValidationError<Self::R>> {
        find_first_path_from_items(
            self.bundle_subjects(),
            &self.chain(),
            |c: &ChainItem<Self::R>| issuer_pks.iter().any(|pk| c.was_issued_by_public_key(pk)),
            list,
            clock,
            TRAVERSAL_LIMIT,
        )
        .map(|_| ())
    }

    /// Returns a vec of each valid path through the chain to the supplied issuer public key.
    /// If none are found an empty vec will be returned.
    fn find_all_paths_to_issuers(
        &self,
        issuer_pks: &[PublicKey],
        list: Option<&RevocationList>,
        clock: &impl Clock,
    ) -> Result<Vec<ValidPath<Self::R>>, ChainValidationError<Self::R>> {
        let success_fn =
            |c: &ChainItem<Self::R>| issuer_pks.iter().any(|pk| c.was_issued_by_public_key(pk));
        find_all_paths_to_issuers(
            &self.bundle_subjects(),
            &self.chain(),
            success_fn,
            list,
            clock,
            TRAVERSAL_LIMIT,
        )
    }

    /// Returns all items which do not form part of a valid path to the issuer public key.
    /// These items may not be valid.
    /// Items are returned even if the traversal limit is reached, to allow the inspect tool to continue to function.
    /// This function is not used by servers, where a traversal limit must be applied to prevent a large certificate
    /// chain from consuming excessive resources.
    fn find_items_not_part_of_valid_path(
        &self,
        issuer_pks: &[PublicKey],
        list: Option<&RevocationList>,
        clock: &impl Clock,
    ) -> Vec<ChainItem<Self::R>> {
        let subjects = self.bundle_subjects();
        let chain = self.chain();

        let success_fn =
            |c: &ChainItem<Self::R>| issuer_pks.iter().any(|pk| c.was_issued_by_public_key(pk));

        let all_valid_certs: Vec<_> =
            find_all_paths_to_issuers(&subjects, &chain, success_fn, list, clock, TRAVERSAL_LIMIT)
                .unwrap_or_default()
                .into_iter()
                .flatten()
                .collect();

        chain
            .into_iter()
            .chain(subjects)
            .filter(|x| !all_valid_certs.contains(x))
            .collect()
    }

    /// Finds a valid path to a certificate of the specified hierarchy level.
    /// If a path is not found then all invalid items up to the specified level are returned.
    fn path_to_cert_with_hierarchy_level(
        &self,
        level: &HierarchyKind,
        clock: &impl Clock,
    ) -> Result<ValidPath<Self::R>, ChainValidationError<Self::R>> {
        let subjects = self.bundle_subjects();
        let chain = self.chain();

        find_first_path_from_items(
            subjects,
            &chain,
            |c: &ChainItem<Self::R>| c.is_at_hierarchy_level(level),
            None,
            clock,
            TRAVERSAL_LIMIT,
        )
        .map_err(|error| {
            if let ChainValidationError::InvalidItems(invalid_items) = error {
                // Return only relevant invalid items
                let invalid_items = invalid_items
                    .into_iter()
                    .filter(|ChainItemValidationError { item, .. }| {
                        item.is_at_or_below_hierarchy_level(level)
                    })
                    .collect();
                ChainValidationError::invalid_items(invalid_items)
            } else {
                error
            }
        })
    }

    /// Identifies items that will expire at the specified number of days in the future or earlier.
    /// Only returns valid items up to the leaf certificate.
    fn expiry_within_days(&self, days: i64, clock: &impl Clock) -> Vec<ChainItem<Self::R>> {
        let path_to_leaf = self
            .path_to_cert_with_hierarchy_level(&HierarchyKind::Leaf, clock)
            .unwrap_or_default();

        let expiry_check_ts = clock.unix_timestamp() + Duration::days(days).whole_seconds();
        path_to_leaf
            .into_iter()
            .filter(|item| item.expiration().not_valid_after <= expiry_check_ts)
            .collect()
    }

    /// Identifies items that will expire at the specified number of days in the future or earlier.
    /// Excludes items whose total validity period is less than or equal to the specified number of days.
    /// Only returns valid items up to the leaf certificate.
    fn expiry_within_days_excluding_shorter_validity(
        &self,
        days: i64,
        clock: &impl Clock,
    ) -> Vec<ChainItem<Self::R>> {
        let days_in_seconds = time::Duration::days(days).whole_seconds();
        self.expiry_within_days(days, clock)
            .into_iter()
            .filter(|item| {
                let expiration = item.expiration();
                let item_validity_duration =
                    expiration.not_valid_after - expiration.not_valid_before;
                item_validity_duration > days_in_seconds
            })
            .collect()
    }

    /// Identifies items that will expire at the specified number of days in the future or earlier.
    /// Excludes items whose total validity period is less than or equal to the specified number of days.
    /// Only returns valid items up to the leaf certificate.
    /// Also returns the timestamp of the earliest expiry within the returned items.
    fn check_for_expiry_warning(&self, days: i64, clock: &impl Clock) -> Option<ExpiryWarning> {
        let expiring_items = self.expiry_within_days_excluding_shorter_validity(days, clock);

        if expiring_items.is_empty() {
            return None;
        }

        let first_expiry = expiring_items
            .iter()
            .map(|item| item.expiration().not_valid_after)
            .min()
            .unwrap();

        let expiring_item_digests = expiring_items
            .into_iter()
            .map(|item| item.into_digest())
            .collect();

        Some(ExpiryWarning {
            expiring_items: expiring_item_digests,
            first_expiry,
        })
    }

    /// Items included with the bundle's main certificate(s) or token in order to prove their provenance
    fn chain(&self) -> Chain<Self::R>;

    /// The main certificate(s) or token which are the focus of the bundle
    fn bundle_subjects(&self) -> Vec<ChainItem<Self::R>>;
}

fn find_valid_issuers<R: Role>(
    item: &ChainItem<R>,
    chain: &Chain<R>,
    list: Option<&RevocationList>,
    clock: &impl Clock,
) -> Vec<ChainItem<R>> {
    chain
        .into_iter()
        .filter(|chain_item| {
            item.valid_issuance_by(chain_item) && chain_item.validate(list, clock).is_ok()
        })
        .cloned()
        .collect::<Vec<_>>()
}

/// Finds the first valid path from any item in `items` to a chain item that satisfies the success function.
/// If a path is not found then all invalid items are returned.
fn find_first_path_from_items<R: Role>(
    items: Vec<ChainItem<R>>,
    chain: &Chain<R>,
    success_fn: impl Fn(&ChainItem<R>) -> bool,
    list: Option<&RevocationList>,
    clock: &impl Clock,
    traversal_limit: usize,
) -> Result<ValidPath<R>, ChainValidationError<R>> {
    find_all_paths_to_issuers(&items, chain, success_fn, list, clock, traversal_limit)
        .map(|paths| paths.into_iter().next().unwrap_or_default())
}

/// Finds all possible paths to issuer public keys from each item in `start_points`
fn find_all_paths_to_issuers<R>(
    start_points: &[ChainItem<R>],
    chain: &Chain<R>,
    success_fn: impl Fn(&ChainItem<R>) -> bool,
    list: Option<&RevocationList>,
    clock: &impl Clock,
    traversal_limit: usize,
) -> Result<Vec<ValidPath<R>>, ChainValidationError<R>>
where
    R: Role,
{
    let issuers = |item: &ChainItem<R>| find_valid_issuers(item, chain, list, clock);

    let mut invalid_items = vec![];
    let mut valid_items = vec![];

    for item in start_points {
        match item.validate(list, clock) {
            Ok(()) => valid_items.push(item.clone()),
            Err(error) => invalid_items.push(ChainItemValidationError::new(item.to_owned(), error)),
        }
    }

    let mut paths = Vec::new();
    let mut visited = HashSet::new();
    let mut current_path = Vec::new();
    all_dfs_paths(
        &valid_items,
        &issuers,
        &success_fn,
        &mut visited,
        &mut current_path,
        &mut paths,
        traversal_limit,
    )?;

    if paths.is_empty() {
        for chain_item in chain {
            if let Err(err) = chain_item.validate(list, clock) {
                invalid_items.push(ChainItemValidationError::new(chain_item.clone(), err))
            }
        }
        return Err(ChainValidationError::invalid_items(invalid_items));
    }
    Ok(paths)
}

// Finds all paths from the start points to a node that satisfies the success function.
// Searches in depth-first order.
fn all_dfs_paths<C, F, G>(
    current_nodes: &[C],
    find_neighbours: &F,
    success: &G,
    visited: &mut HashSet<C>,
    path: &mut Vec<C>,
    paths: &mut Vec<Vec<C>>,
    visit_limit: usize,
) -> Result<(), VisitLimitReached>
where
    C: Eq + Hash + Clone,
    F: Fn(&C) -> Vec<C>,
    G: Fn(&C) -> bool,
{
    for node in current_nodes {
        if !visited.contains(node) {
            visited.insert(node.clone());
            if visited.len() >= visit_limit {
                return Err(VisitLimitReached);
            }
            path.push(node.clone());

            if success(node) {
                paths.push(path.clone());
            } else {
                let neighbors = find_neighbours(node);
                all_dfs_paths(
                    &neighbors,
                    find_neighbours,
                    success,
                    visited,
                    path,
                    paths,
                    visit_limit,
                )?;
            }
            path.pop();
            visited.remove(node);
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
struct VisitLimitReached;

impl Display for VisitLimitReached {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Visit limit reached")
    }
}

impl<R: Role> From<VisitLimitReached> for ChainValidationError<R> {
    fn from(_: VisitLimitReached) -> Self {
        ChainValidationError::TraversalLimitReached
    }
}

/// Items nearing expiration and the earliest of their expiry dates as a unix timestamp
#[derive(Serialize)]
// tsgen
pub struct ExpiryWarning {
    expiring_items: Vec<ChainItemDigest>,
    first_expiry: i64,
}

#[cfg(all(test, feature = "cert_tests"))]
mod tests {
    use crate::EtrBuilder;
    use crate::key_traits::HasAssociatedSigningKey;
    use crate::test_helpers::{
        create_etr_with_options, create_issuing_exemption_token_bundle, create_leaf_bundle,
    };
    use crate::test_helpers::{create_exemption_token_bundle, create_exemptions};
    use crate::tokens::exemption::et::issue_exemption_token_without_compliance_check;
    use crate::validation_error::InvalidityCause;
    use crate::{Authenticator, CertificateChain, SystemClock, YubikeyId};
    use crate::{
        Builder, Certificate, CertificateBundle, CertificateRequest, Description,
        ExemptionTokenGroup, Expiration, GenbankId, Issued, KeyUnavailable, Organism,
        SequenceIdentifier, SigningKeyPair, TokenBundle, TokenGroup,
        certificate::{IssuerAdditionalFields, RequestBuilder},
        shared_components::role::Exemption,
        test_for_all_token_types,
        test_helpers::{
            BreakableSignature, create_cross_signed_intermediate_bundle, create_etr,
            create_intermediate_bundle,
        },
    };

    use super::*;

    #[test]
    fn can_traverse_from_intermediate_to_root() {
        let kp = SigningKeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = SigningKeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let int_cert_bundle = CertificateBundle::new(intermediate_cert, None);

        int_cert_bundle
            .validate_path_to_issuers(&[*root_cert.public_key()], None, &SystemClock)
            .expect("should find path to root");
    }

    #[test]
    fn can_not_traverse_from_intermediate_to_incorrect_root() {
        let kp_1 = SigningKeyPair::new_random();
        let root_cert_1 = RequestBuilder::<Exemption>::root_v1_builder(kp_1.public_key())
            .build()
            .load_key(kp_1)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let kp_2 = SigningKeyPair::new_random();
        let root_cert_2 = RequestBuilder::<Exemption>::root_v1_builder(kp_2.public_key())
            .build()
            .load_key(kp_2)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = SigningKeyPair::new_random();
        let intermediate_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert_1
            .issue_cert(intermediate_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let int_certificate_bundle = CertificateBundle::new(intermediate_cert, None);

        int_certificate_bundle
            .validate_path_to_issuers(&[*root_cert_2.public_key()], None, &SystemClock)
            .expect_err("should not find path to root");
    }

    #[test]
    fn can_traverse_from_leaf_to_root() {
        let kp = SigningKeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = SigningKeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .unwrap();

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = intermediate_cert
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let int_certificate_bundle = CertificateBundle::new(intermediate_cert, None);

        let cert_chain = int_certificate_bundle.issue_chain();
        let leaf_certificate_bundle = CertificateBundle::new(leaf_cert, Some(cert_chain));

        leaf_certificate_bundle
            .validate_path_to_issuers(&[*root_cert.public_key()], None, &SystemClock)
            .expect("should find path to root");
    }

    #[test]
    fn can_traverse_from_leaf_to_root_via_alternative_intermediate() {
        let kp = SigningKeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = SigningKeyPair::new_random();
        let int_req_a =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();
        let int_req_b = int_req_a.clone();

        let intermediate_cert_a = root_cert
            .issue_cert(int_req_a, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .expect("Could not load key");

        let leaf_kp = SigningKeyPair::new_random();
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
            .validate_path_to_issuers(&[*root_cert.public_key()], None, &SystemClock)
            .expect("should find path to root");
    }

    #[test]
    fn can_find_all_paths_from_leaf_to_multiple_roots() {
        let root_kp_a = SigningKeyPair::new_random();
        let root_cert_a = RequestBuilder::<Exemption>::root_v1_builder(root_kp_a.public_key())
            .build()
            .load_key(root_kp_a)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_kp_b = SigningKeyPair::new_random();
        let root_cert_b = RequestBuilder::<Exemption>::root_v1_builder(root_kp_b.public_key())
            .build()
            .load_key(root_kp_b)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let int_kp = SigningKeyPair::new_random();
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

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = int_cert_bundle
            .get_lead_cert(&SystemClock)
            .unwrap()
            .to_owned()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let chain = int_cert_bundle.issue_chain();
        let leaf_bundle = CertificateBundle::new(leaf_cert, Some(chain));

        let paths_to_root_a = leaf_bundle
            .find_all_paths_to_issuers(&[*root_cert_a.public_key()], None, &SystemClock)
            .expect("should find path to root a");

        let paths_to_root_b = leaf_bundle
            .find_all_paths_to_issuers(&[*root_cert_b.public_key()], None, &SystemClock)
            .expect("should find path to root b");

        let all_paths = leaf_bundle
            .find_all_paths_to_issuers(
                &[*root_cert_a.public_key(), *root_cert_b.public_key()],
                None,
                &SystemClock,
            )
            .expect("should find paths");

        assert!(paths_to_root_a.len() == 1);
        assert!(paths_to_root_b.len() == 1);
        assert!(all_paths.len() == 2)
    }

    #[test]
    fn can_find_certs_which_are_not_part_of_valid_path() {
        let root_kp_a = SigningKeyPair::new_random();
        let root_cert_a = RequestBuilder::<Exemption>::root_v1_builder(root_kp_a.public_key())
            .build()
            .load_key(root_kp_a)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let int_kp = SigningKeyPair::new_random();
        let intermediate_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert_a
            .issue_cert(intermediate_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        let int_cert_bundle = CertificateBundle::new(intermediate_cert, None);

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = int_cert_bundle
            .get_lead_cert(&SystemClock)
            .unwrap()
            .to_owned()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        // Create a certificate which has nothing to do with the others
        let root_kp_b = SigningKeyPair::new_random();
        let root_cert_b = RequestBuilder::<Exemption>::root_v1_builder(root_kp_b.public_key())
            .build()
            .load_key(root_kp_b)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign")
            .into_key_unavailable();

        let mut chain = int_cert_bundle.issue_chain();
        chain.add_item(root_cert_b.clone());
        let leaf_bundle = CertificateBundle::new(leaf_cert, Some(chain));

        let excluded_certs = leaf_bundle.find_items_not_part_of_valid_path(
            &[*root_cert_a.public_key()],
            None,
            &SystemClock,
        );
        assert_eq!(excluded_certs.len(), 1);
        assert_eq!(excluded_certs[0], root_cert_b.into());
    }

    #[test]
    fn intermediate_cert_with_invalid_signature_is_not_used_to_build_path() {
        let kp = SigningKeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = SigningKeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .unwrap();

        let leaf_kp = SigningKeyPair::new_random();
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
            .validate_path_to_issuers(&[*root_cert.public_key()], None, &SystemClock)
            .expect_err("should not find path to root");

        let result = leaf_certificate_bundle.find_all_paths_to_issuers(
            &[*root_cert.public_key()],
            None,
            &SystemClock,
        );

        let excluded_certs = leaf_certificate_bundle.find_items_not_part_of_valid_path(
            &[*root_cert.public_key()],
            None,
            &SystemClock,
        );

        assert!(result.is_err());
        assert_eq!(excluded_certs[0], intermediate_cert.into());
    }

    #[test]
    fn leaf_cert_with_invalid_signature_is_not_used_to_build_path() {
        let kp = SigningKeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = SigningKeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .unwrap();

        let leaf_kp = SigningKeyPair::new_random();
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
            .validate_path_to_issuers(&[*root_cert.public_key()], None, &SystemClock)
            .expect_err("should not find path to root");

        let result = leaf_certificate_bundle.find_all_paths_to_issuers(
            &[*root_cert.public_key()],
            None,
            &SystemClock,
        );

        let excluded_certs = leaf_certificate_bundle.find_items_not_part_of_valid_path(
            &[*root_cert.public_key()],
            None,
            &SystemClock,
        );

        assert!(result.is_err());
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
            .validate_path_to_issuers(&[root_pk], None, &SystemClock)
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
            .validate_path_to_issuers(
                &[SigningKeyPair::new_random().public_key()],
                None,
                &SystemClock,
            )
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
            .validate_path_to_issuers(
                &[SigningKeyPair::new_random().public_key()],
                None,
                &SystemClock,
            )
            .expect_err("should not find path to root");
    }

    test_for_all_token_types!(cannot_traverse_to_root_with_token_revoked_via_issuance_id);
    fn cannot_traverse_to_root_with_token_revoked_via_issuance_id<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
    {
        let (token_bundle, _) = create_token_bundle_fn();
        let issuance_id = token_bundle.token.issuance_id();

        let revocation_list = RevocationList::default().with_issuance_id(*issuance_id);

        let error = token_bundle
            .validate_path_to_issuers(
                &[SigningKeyPair::new_random().public_key()],
                Some(&revocation_list),
                &SystemClock,
            )
            .expect_err("should not validate");

        let invalid_items = error.expect_invalid_items();
        let ChainItemValidationError { item, error } = invalid_items
            .first()
            .expect("chain error should have invalid items");

        assert_eq!(item, &token_bundle.token.into());
        assert!(error.causes.contains(&InvalidityCause::Revoked));
    }

    test_for_all_token_types!(cannot_traverse_to_root_with_token_revoked_via_request_id);
    fn cannot_traverse_to_root_with_token_revoked_via_request_id<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
    {
        let (token_bundle, _) = create_token_bundle_fn();
        let request_id = token_bundle.token.request_id();

        let revocation_list = RevocationList::default().with_request_id(*request_id);

        let error = token_bundle
            .validate_path_to_issuers(
                &[SigningKeyPair::new_random().public_key()],
                Some(&revocation_list),
                &SystemClock,
            )
            .expect_err("should not validate");

        let invalid_items = error.expect_invalid_items();
        let ChainItemValidationError { item, error } = invalid_items
            .first()
            .expect("chain error should have invalid items");

        assert_eq!(item, &token_bundle.token.into());
        assert!(error.causes.contains(&InvalidityCause::Revoked));
    }

    mod cannot_traverse_to_root_with_token_revoked_via_public_key {
        #[test]
        fn for_database() {
            super::cannot_traverse_to_root_with_token_revoked_via_public_key(
                crate::test_helpers::create_database_token_bundle,
            )
        }

        #[test]
        fn for_hlt() {
            super::cannot_traverse_to_root_with_token_revoked_via_public_key(
                crate::test_helpers::create_hlt_token_bundle,
            )
        }

        #[test]
        fn for_keyserver() {
            super::cannot_traverse_to_root_with_token_revoked_via_public_key(
                crate::test_helpers::create_keyserver_token_bundle,
            )
        }

        #[test]
        fn for_synthesizer() {
            super::cannot_traverse_to_root_with_token_revoked_via_public_key(
                crate::test_helpers::create_synthesizer_token_bundle,
            )
        }
    }

    fn cannot_traverse_to_root_with_token_revoked_via_public_key<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
        T::Token: HasAssociatedSigningKey,
    {
        let (token_bundle, _) = create_token_bundle_fn();
        let public_key = token_bundle.token.public_key();

        let revocation_list = RevocationList::default().with_public_key(*public_key);

        let error = token_bundle
            .validate_path_to_issuers(
                &[SigningKeyPair::new_random().public_key()],
                Some(&revocation_list),
                &SystemClock,
            )
            .expect_err("should not validate");

        let invalid_items = error.expect_invalid_items();

        let ChainItemValidationError { item, error } = invalid_items
            .first()
            .expect("chain error should have invalid items");

        assert_eq!(item, &token_bundle.token.clone().into());
        assert!(error.causes.contains(&InvalidityCause::Revoked));
    }

    test_for_all_token_types!(
        all_relevant_causes_for_token_invalidity_included_in_chain_validation_error
    );
    fn all_relevant_causes_for_token_invalidity_included_in_chain_validation_error<F, T>(
        create_token_bundle_fn: F,
    ) where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
    {
        let (mut token_bundle, _) = create_token_bundle_fn();
        token_bundle.token.break_signature();
        let request_id = token_bundle.token.request_id();

        let revocation_list = RevocationList::default().with_request_id(*request_id);

        let error = token_bundle
            .validate_path_to_issuers(
                &[SigningKeyPair::new_random().public_key()],
                Some(&revocation_list),
                &SystemClock,
            )
            .expect_err("should not validate");

        let invalid_items = error.expect_invalid_items();
        let ChainItemValidationError { item, error } = invalid_items
            .first()
            .expect("chain error should have invalid items");

        assert_eq!(item, &token_bundle.token.clone().into());
        assert!(error.causes.contains(&InvalidityCause::Revoked));
        assert!(error.causes.contains(&InvalidityCause::SignatureFailure));
    }

    test_for_all_token_types!(can_identify_redundant_certificates);
    fn can_identify_redundant_certificates<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
        <T as TokenGroup>::AssociatedRole: Debug,
        RequestBuilder<T::AssociatedRole>:
            Builder<Item = CertificateRequest<T::AssociatedRole, KeyUnavailable>>,
    {
        let (token_bundle, _) = create_token_bundle_fn();
        let incorrect_root = SigningKeyPair::new_random().public_key();
        let items_not_part_of_path =
            token_bundle.find_items_not_part_of_valid_path(&[incorrect_root], None, &SystemClock);
        assert!(items_not_part_of_path.contains(&token_bundle.token.into()));
    }

    #[test]
    fn cannot_find_path_to_root_from_token_with_invalid_leaf() {
        let kp = SigningKeyPair::new_random();
        let root_pk = kp.public_key();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = SigningKeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert")
            .load_key(int_kp)
            .unwrap();

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let mut leaf_cert = intermediate_cert
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let int_cert_bundle = CertificateBundle::new(intermediate_cert, None);
        let chain = int_cert_bundle.issue_chain();

        leaf_cert.break_signature();
        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let token_request = create_etr(create_exemptions());
        let token = leaf_cert
            .load_key(leaf_kp)
            .unwrap()
            .issue_exemption_token(token_request, Expiration::default(), vec![])
            .unwrap();
        let token_chain = leaf_bundle.issue_chain();
        let token_bundle = TokenBundle::<ExemptionTokenGroup>::new(token, token_chain);

        token_bundle
            .validate_path_to_issuers(&[root_pk], None, &SystemClock)
            .expect_err("should not find path to root");
    }

    #[test]
    fn cannot_find_path_to_root_from_token_with_invalid_intermediate() {
        let kp = SigningKeyPair::new_random();
        let root_pk = kp.public_key();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = SigningKeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let mut intermediate_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .expect("Couldn't issue cert");

        // break signature of intermediate cert
        intermediate_cert.break_signature();
        let int_cert_bundle = CertificateBundle::new(intermediate_cert.clone(), None);

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = intermediate_cert
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let chain = int_cert_bundle.issue_chain();

        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let token_request = create_etr(create_exemptions());
        let token = leaf_cert
            .load_key(leaf_kp)
            .unwrap()
            .issue_exemption_token(token_request, Expiration::default(), vec![])
            .unwrap();
        let token_chain = leaf_bundle.issue_chain();
        let token_bundle = TokenBundle::<ExemptionTokenGroup>::new(token, token_chain);

        token_bundle
            .validate_path_to_issuers(&[root_pk], None, &SystemClock)
            .expect_err("should not find path to root");
    }

    #[test]
    fn can_identify_items_in_path_to_root_from_et_bundle() {
        let (int_bundle, int_kp, root_pk) = create_intermediate_bundle::<Exemption>();

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let int_cert = int_bundle.get_lead_cert(&SystemClock).unwrap().clone();

        let leaf_cert = int_cert
            .clone()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .unwrap();

        let chain = int_bundle.issue_chain();
        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let etr = create_etr(create_exemptions());

        let et = leaf_bundle
            .get_lead_cert(&SystemClock)
            .unwrap()
            .clone()
            .load_key(leaf_kp)
            .unwrap()
            .issue_exemption_token(etr, Expiration::default(), vec![])
            .unwrap();

        let chain = leaf_bundle.issue_chain();

        let et_bundle = TokenBundle::<ExemptionTokenGroup>::new(et.clone(), chain);

        let all_paths = et_bundle
            .find_all_paths_to_issuers(&[root_pk], None, &SystemClock)
            .expect("should find paths");

        // assert that only one path to issuer found
        assert_eq!(all_paths.len(), 1);

        // assert that path to issuer contains three
        assert_eq!(all_paths[0].len(), 3);

        // assert that path to issuer contains token, leaf cert and int cert
        assert!(all_paths[0].contains(&(et.into())));
        assert!(all_paths[0].contains(&(leaf_cert.into())));
        assert!(all_paths[0].contains(&(int_cert.into())));
    }

    #[test]
    fn can_identify_certificates_in_cross_signed_path_to_root_from_et_bundle() {
        let (int_bundle, int_kp, root_pk) = create_cross_signed_intermediate_bundle::<Exemption>();

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let int_cert: &Certificate<Exemption, _> = int_bundle.get_lead_cert(&SystemClock).unwrap();

        let leaf_cert = int_cert
            .clone()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .unwrap();

        let chain = int_bundle.issue_chain();
        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let etr = create_etr(create_exemptions());

        let et = leaf_bundle
            .get_lead_cert(&SystemClock)
            .unwrap()
            .clone()
            .load_key(leaf_kp)
            .unwrap()
            .issue_exemption_token(etr, Expiration::default(), vec![])
            .unwrap();

        let chain = leaf_bundle.issue_chain();

        let et_bundle = TokenBundle::<ExemptionTokenGroup>::new(et.clone(), chain);

        let all_paths = et_bundle
            .find_all_paths_to_issuers(&[root_pk], None, &SystemClock)
            .expect("should find paths");

        // assert that two paths to issuer found
        assert_eq!(all_paths.len(), 2);

        let expected_path_1: Vec<ChainItem<Exemption>> = vec![
            et.clone().into(),
            leaf_cert.clone().into(),
            int_bundle.certs[0].clone().into(),
        ];
        let expected_path_2: Vec<ChainItem<Exemption>> = vec![
            et.clone().into(),
            leaf_cert.into(),
            int_bundle.certs[1].clone().into(),
        ];

        // assert that expected paths to issuer are found
        assert!(all_paths.contains(&(expected_path_1)));
        assert!(all_paths.contains(&(expected_path_2)));
    }

    #[test]
    fn can_traverse_from_child_et_to_root() {
        let (et_bundle, et_kp, root_pub) = create_issuing_exemption_token_bundle();

        let child_etr = create_etr_with_options(None, vec![], vec![]);
        let child_et = et_bundle
            .token
            .clone()
            .load_key(et_kp)
            .unwrap()
            .issue_exemption_token(child_etr, Expiration::default(), vec![])
            .unwrap();
        let child_et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(child_et, et_bundle.issue_chain());
        child_et_bundle
            .validate_path_to_issuers(&[root_pub], None, &SystemClock)
            .expect("traversal should succeed");
    }

    #[test]
    fn traversal_fails_where_child_et_has_associated_keypair() {
        let (et_bundle, et_kp, root_pub) = create_issuing_exemption_token_bundle();

        let child_kp = SigningKeyPair::new_random();
        let child_etr = create_etr_with_options(Some(child_kp.public_key()), vec![], vec![]);
        let child_et =
            issue_exemption_token_without_compliance_check(child_etr, &et_kp, vec![], vec![]);
        let child_et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(child_et, et_bundle.issue_chain());
        child_et_bundle
            .validate_path_to_issuers(&[root_pub], None, &SystemClock)
            .expect_err("traversal should fail");
    }

    #[test]
    fn traversal_fails_where_child_et_has_shipping_address_not_found_on_issuer() {
        let (et_bundle, et_kp, root_pub) = create_issuing_exemption_token_bundle();

        let shipping_address = vec!["22 New Street".to_string(), "Some Other City".to_string()];
        let etr = EtrBuilder::new()
            .shipping_addresses(vec![shipping_address])
            .build_v1();

        let child_et = issue_exemption_token_without_compliance_check(etr, &et_kp, vec![], vec![]);
        let child_et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(child_et, et_bundle.issue_chain());
        child_et_bundle
            .validate_path_to_issuers(&[root_pub], None, &SystemClock)
            .expect_err("traversal should fail");
    }

    #[test]
    fn traversal_fails_where_child_et_has_exemptions_not_found_on_issuer() {
        let (et_bundle, et_kp, root_pub) = create_issuing_exemption_token_bundle();

        let exemption = Organism::new(
            "test",
            vec![SequenceIdentifier::Id(GenbankId::try_new("555").unwrap())],
        );
        let etr = EtrBuilder::new().exemptions(vec![exemption]).build_v1();

        let child_et = issue_exemption_token_without_compliance_check(etr, &et_kp, vec![], vec![]);
        let child_et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(child_et, et_bundle.issue_chain());
        child_et_bundle
            .validate_path_to_issuers(&[root_pub], None, &SystemClock)
            .expect_err("traversal should fail");
    }

    #[test]
    fn traversal_fails_where_child_et_is_missing_emails_to_notify_from_issuer() {
        let (leaf_bundle, leaf_kp, root_pub) = create_leaf_bundle::<Exemption>();

        let et_kp = SigningKeyPair::new_random();
        let issuing_etr = EtrBuilder::new().public_key(et_kp.public_key()).build_v1();

        let emails_to_notify = vec!["must_notify@example.com".into()];
        let issuing_et = issue_exemption_token_without_compliance_check(
            issuing_etr,
            &leaf_kp,
            emails_to_notify,
            vec![],
        );

        let et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(issuing_et, leaf_bundle.issue_chain());

        let child_etr = EtrBuilder::new().build_v1();

        let child_et =
            issue_exemption_token_without_compliance_check(child_etr, &et_kp, vec![], vec![]);
        let child_et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(child_et, et_bundle.issue_chain());
        child_et_bundle
            .validate_path_to_issuers(&[root_pub], None, &SystemClock)
            .expect_err("traversal should fail");
    }

    #[test]
    fn traversal_fails_where_child_et_is_missing_issuer_auth_devices_from_issuer() {
        let (leaf_bundle, leaf_kp, root_pub) = create_leaf_bundle::<Exemption>();

        let et_kp = SigningKeyPair::new_random();
        let issuing_etr = EtrBuilder::new().public_key(et_kp.public_key()).build_v1();

        let issuer_auth_devices = vec![Authenticator::Yubikey(
            YubikeyId::try_new("cccccccccccc").unwrap(),
        )];

        let issuing_et = issue_exemption_token_without_compliance_check(
            issuing_etr,
            &leaf_kp,
            vec![],
            issuer_auth_devices,
        );

        let et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(issuing_et, leaf_bundle.issue_chain());

        let child_etr = EtrBuilder::new().build_v1();

        let child_et =
            issue_exemption_token_without_compliance_check(child_etr, &et_kp, vec![], vec![]);
        let child_et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(child_et, et_bundle.issue_chain());
        child_et_bundle
            .validate_path_to_issuers(&[root_pub], None, &SystemClock)
            .expect_err("traversal should fail");
    }

    #[test]
    fn traversal_for_child_et_fails_where_issuing_et_is_revoked() {
        let (et_bundle, et_kp, root_pub) = create_issuing_exemption_token_bundle();
        let et_public_key = et_kp.public_key();
        let child_etr = create_etr_with_options(None, vec![], vec![]);
        let child_et = et_bundle
            .token
            .clone()
            .load_key(et_kp)
            .unwrap()
            .issue_exemption_token(child_etr, Expiration::default(), vec![])
            .unwrap();
        let child_et_bundle =
            TokenBundle::<ExemptionTokenGroup>::new(child_et, et_bundle.issue_chain());
        let revocation_list = RevocationList::default().with_public_key(et_public_key);
        child_et_bundle
            .validate_path_to_issuers(&[root_pub], Some(&revocation_list), &SystemClock)
            .expect_err("traversal should fail");
    }

    #[test]
    fn can_check_for_impending_expiry() {
        let (et_bundle, _) = create_exemption_token_bundle();

        let within_default = et_bundle.expiry_within_days(Expiration::DEFAULT_DAYS, &SystemClock);
        assert_eq!(within_default.len(), 2);

        let within_one_day = et_bundle.expiry_within_days(1, &SystemClock);
        assert_eq!(within_one_day.len(), 0);
    }

    #[test]
    fn can_check_for_impending_expiry_with_exclusion() {
        let (et_bundle, _) = create_exemption_token_bundle();

        let within_default = et_bundle
            .expiry_within_days_excluding_shorter_validity(Expiration::DEFAULT_DAYS, &SystemClock);
        assert_eq!(within_default.len(), 0);
    }

    #[test]
    fn user_friendly_text_for_invalid_chain_is_correct() {
        let (int_bundle, int_kp, root) = create_intermediate_bundle::<Exemption>();
        let leaf_kp = SigningKeyPair::new_random();
        let leaf_public_key = leaf_kp.public_key();
        let leaf_request = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_public_key)
            .with_description(
                Description::default()
                    .with_name("Harry")
                    .with_email("harry@example.com"),
            )
            .build();
        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_request, IssuerAdditionalFields::default(), int_kp)
            .unwrap();
        let exemption_request = EtrBuilder::new()
            .requestor(
                Description::default()
                    .with_name("Researcher A")
                    .with_email("r.a@example.com"),
            )
            .build_v1();
        let mut exemption_bundle = leaf_bundle
            .issue_exemption_token_bundle(exemption_request, Expiration::default(), vec![], leaf_kp)
            .unwrap();

        exemption_bundle.token.break_signature();

        let revocation_list = RevocationList::default().with_public_key(leaf_public_key);
        let err = exemption_bundle
            .validate_path_to_issuers(&[root], Some(&revocation_list), &SystemClock)
            .unwrap_err();

        let expected = format!(
            "the leaf certificate belonging to 'Harry, harry@example.com' \
            (public key: {leaf_public_key}) is not valid due to revocation, \
            the exemption token belonging to 'Researcher A, r.a@example.com' is not valid due to \
            signature verification failure"
        );
        assert_eq!(err.user_friendly_text(), expected);
    }

    #[test]
    fn traversal_limit_is_applied() {
        let test_traversal_limit = 5;
        let kp = SigningKeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let root_cert_pk = *root_cert.public_key();

        let mut current_cert = root_cert;
        let mut chain = CertificateChain::new();

        // Create a chain of intermediate certificates that will exceed our test limit
        for _ in 0..test_traversal_limit - 1 {
            let int_kp = SigningKeyPair::new_random();
            let int_req =
                RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

            let intermediate_cert = current_cert
                .issue_cert(int_req, IssuerAdditionalFields::default())
                .expect("Couldn't issue cert");

            chain.add_item(intermediate_cert.clone());
            current_cert = intermediate_cert.load_key(int_kp).unwrap();
        }

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = current_cert
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .expect("Could not sign leaf cert");

        let leaf_bundle = CertificateBundle::new(leaf_cert, Some(chain));

        let result = find_all_paths_to_issuers(
            &leaf_bundle.bundle_subjects(),
            &leaf_bundle.chain(),
            |c: &ChainItem<Exemption>| c.was_issued_by_public_key(&root_cert_pk),
            None,
            &SystemClock,
            test_traversal_limit,
        );

        assert!(matches!(
            result,
            Err(ChainValidationError::TraversalLimitReached)
        ));
    }
}
