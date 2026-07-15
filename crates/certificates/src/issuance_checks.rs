// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::key::EncryptableKeypair;
use crate::key::error::KeyLoadError;
use crate::key::signing::SigningKeyPair;
use crate::{
    CertificateBundle, ChainItemDigestValidationError, ChainTraversal, ExemptionTokenGroup,
    ExemptionTokenRequest, HierarchyKind, KeyMismatchError, Role, TokenBundle, TokenGroup,
    certificate::certificate_bundle::CertificateError,
    key_traits::CanLoadSigningKey,
    tokens::exemption::et::{EtLoadKeyError, NonCompliantChildToken},
    traversal::ExpiryWarning,
};
use crate::{ChainValidationError, Clock};

/// For checking a certificate bundle before issuing a token.
/// Checks that the cert bundle contains valid certificates up to an intermediate certificate.
/// If no valid cert is found, an invalid cert digest is returned with corresponding validation errors.
/// If there is a valid cert, returns any items up to the leaf that are
/// expiring within the given number of days (excludes shorter validity periods).
pub fn precheck_cert_bundle<R: Role>(
    cert_bundle: CertificateBundle<R>,
    expiring_within_days: i64,
    clock: &impl Clock,
) -> Result<Option<ExpiryWarning>, CertBundlePreIssuanceError> {
    cert_bundle.get_lead_cert(clock)?;
    cert_bundle.path_to_cert_with_hierarchy_level(&HierarchyKind::Intermediate, clock)?;
    Ok(cert_bundle.check_for_expiry_warning(expiring_within_days, clock))
}

/// For checking that a key can be decrypted and corresponds to the supplied certificate.
/// Checks that the cert bundle contains a valid certificate (not checking this would require unwrapping).
/// If no valid cert is found, an invalid cert digest is returned with corresponding validation errors.
/// The key is then decrypted and we check that it matches the cert.
pub fn precheck_key<R: Role>(
    cert_bundle: &CertificateBundle<R>,
    key_file_contents: &str,
    passphrase: &str,
    clock: &impl Clock,
) -> Result<(), CertBundlePreIssuanceError> {
    let cert = cert_bundle.get_lead_cert(clock)?;

    let key = SigningKeyPair::load_key(key_file_contents, passphrase)?;
    cert.clone().load_key(key)?;

    Ok(())
}

/// Checks that the exemption token has an associated key.
/// Checks that the exemption token bundle contains a valid path to an intermediate certificate.
/// If both checks pass, returns any items up to the leaf that are
/// expiring within the given number of days (excludes shorter validity periods).
pub fn precheck_et_bundle<R: Role>(
    et_bundle: TokenBundle<ExemptionTokenGroup>,
    expiring_within_days: i64,
    clock: &impl Clock,
) -> Result<Option<ExpiryWarning>, BundleCheckError> {
    if et_bundle.token.try_public_key().is_none() {
        return Err(BundleCheckError::NoKey);
    }

    et_bundle.path_to_cert_with_hierarchy_level(&HierarchyKind::Intermediate, clock)?;
    Ok(et_bundle.check_for_expiry_warning(expiring_within_days, clock))
}

/// For checking that a key can be decrypted and corresponds to the supplied exemption token.
pub fn precheck_et_key(
    et_bundle: TokenBundle<ExemptionTokenGroup>,
    key_file_contents: &str,
    passphrase: &str,
) -> Result<(), BundleCheckError> {
    let key = SigningKeyPair::load_key(key_file_contents, passphrase)?;
    et_bundle.token.load_key(key)?;
    Ok(())
}

/// For checking that a key can be decrypted and corresponds to the supplied token.
/// Cannot be used for exemption tokens, since they have a different key loading interface.
pub fn precheck_token_key<T: TokenGroup, R: Role>(
    bundle: TokenBundle<T>,
    key_file_contents: &str,
    passphrase: &str,
) -> Result<(), BundleCheckError>
where
    T::Token: CanLoadSigningKey,
{
    let key = SigningKeyPair::load_key(key_file_contents, passphrase)?;
    bundle.token.load_key(key)?;
    Ok(())
}

/// Checks whether the child exemption token request is issuable by the parent exemption token.
/// Does not check that the token/chain is valid or even that the exemption token has an associated key.
pub fn precheck_child_etr(
    et_bundle: TokenBundle<ExemptionTokenGroup>,
    child_etr: ExemptionTokenRequest,
) -> Result<(), NonCompliantChildToken> {
    et_bundle.token.check_ability_to_issue(&child_etr)
}

#[derive(Serialize)]
// tsgen
pub enum CertBundlePreIssuanceError {
    /// There is somehow no cert within the bundle.
    /// Shouldn't happen - would be caught when parsing bundle.
    MissingCert,
    /// The cert itself is invalid.
    InvalidCert(Box<ChainItemDigestValidationError>),
    /// One or more certs in the chain are invalid.
    Chain(Vec<ChainItemDigestValidationError>),
    IncorrectPassword,
    /// Either they have messed with their keyfile contents or we have broken compatibility.
    CouldNotParseKey,
    /// The key does not match the cert.
    KeyMismatch,
    /// The chain traversal limit was reached without finding a valid path.
    TraversalLimitReached,
}

#[derive(Serialize)]
// tsgen
pub enum BundleCheckError {
    /// User is attempting to subset with an exemption token with no associated key
    NoKey,
    /// The exemption token and/or leaf cert is invalid
    Chain(Vec<ChainItemDigestValidationError>),
    IncorrectPassword,
    /// Either they have messed with their keyfile contents or we have broken compatibility.
    CouldNotParseKey,
    /// The key does not match the token.
    KeyMismatch,
    /// The chain traversal limit was reached without finding a valid path.
    TraversalLimitReached,
}

impl<R: Role> From<CertificateError<R>> for CertBundlePreIssuanceError {
    fn from(e: CertificateError<R>) -> Self {
        match e {
            CertificateError::Invalid(cert, error) => CertBundlePreIssuanceError::InvalidCert(
                Box::new(ChainItemDigestValidationError::new(*cert, error)),
            ),
            CertificateError::NotFound => CertBundlePreIssuanceError::MissingCert,
        }
    }
}

impl From<KeyLoadError> for CertBundlePreIssuanceError {
    fn from(e: KeyLoadError) -> Self {
        match e {
            KeyLoadError::Decrypt(_) => CertBundlePreIssuanceError::IncorrectPassword,
            KeyLoadError::Decode(_) => CertBundlePreIssuanceError::CouldNotParseKey,
        }
    }
}

impl From<KeyMismatchError> for CertBundlePreIssuanceError {
    fn from(_: KeyMismatchError) -> Self {
        CertBundlePreIssuanceError::KeyMismatch
    }
}

impl From<EtLoadKeyError> for BundleCheckError {
    fn from(e: EtLoadKeyError) -> Self {
        match e {
            EtLoadKeyError::Mismatch(_) => BundleCheckError::KeyMismatch,
            EtLoadKeyError::NoAssociatedKey => BundleCheckError::NoKey,
        }
    }
}

impl From<KeyLoadError> for BundleCheckError {
    fn from(e: KeyLoadError) -> Self {
        match e {
            KeyLoadError::Decrypt(_) => BundleCheckError::IncorrectPassword,
            KeyLoadError::Decode(_) => BundleCheckError::CouldNotParseKey,
        }
    }
}

impl From<KeyMismatchError> for BundleCheckError {
    fn from(_: KeyMismatchError) -> Self {
        BundleCheckError::KeyMismatch
    }
}

impl<R: Role> From<ChainValidationError<R>> for CertBundlePreIssuanceError {
    fn from(e: ChainValidationError<R>) -> Self {
        match e {
            ChainValidationError::InvalidItems(invalid_items) => CertBundlePreIssuanceError::Chain(
                invalid_items.into_iter().map(|ci| ci.into()).collect(),
            ),
            ChainValidationError::TraversalLimitReached => {
                CertBundlePreIssuanceError::TraversalLimitReached
            }
        }
    }
}

impl<R: Role> From<ChainValidationError<R>> for BundleCheckError {
    fn from(e: ChainValidationError<R>) -> Self {
        match e {
            ChainValidationError::InvalidItems(invalid_items) => {
                BundleCheckError::Chain(invalid_items.into_iter().map(|ci| ci.into()).collect())
            }
            ChainValidationError::TraversalLimitReached => BundleCheckError::TraversalLimitReached,
        }
    }
}
