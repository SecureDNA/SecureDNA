// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::{
    certificate::certificate_bundle::CertificateError,
    tokens::exemption::et::{EtLoadKeyError, NonCompliantChildToken},
    traversal::ExpiryWarning,
    CertificateBundle, ChainItemDigestValidationError, ChainTraversal, ExemptionTokenGroup,
    ExemptionTokenRequest, KeyLoadError, KeyMismatchError, KeyPair, Role, TokenBundle,
};

/// Checks that the cert bundle contains a valid certificate.
/// If no valid cert is found, an invalid cert digest is returned with corresponding validation errors.
/// If there is a valid cert, returns any items up to the leaf that are
/// expiring within the given number of days (excludes shorter validity periods).
pub fn cert_bundle_pre_issuance_check<R: Role>(
    cert_bundle: CertificateBundle<R>,
    expiring_within_days: i64,
) -> Result<Option<ExpiryWarning>, CertBundlePreIssuanceError> {
    cert_bundle.get_lead_cert()?;

    Ok(cert_bundle.check_for_expiry_warning(expiring_within_days))
}

/// Checks that the cert bundle contains a valid certificate (not checking this would require unwrapping).
/// If no valid cert is found, an invalid cert digest is returned with corresponding validation errors.
/// The key is decrypted and we check that it matches the cert.
pub fn cert_bundle_and_key_pre_issuance_check<R: Role>(
    cert_bundle: CertificateBundle<R>,
    key_file_contents: &str,
    passphrase: &str,
) -> Result<(), CertBundlePreIssuanceError> {
    let cert = cert_bundle.get_lead_cert()?;

    let key = KeyPair::load_key(key_file_contents, passphrase)?;
    cert.clone().load_key(key)?;

    Ok(())
}

/// Checks that the exemption token has an associated key.
/// Checks that the exemption token bundle contains a valid path to a leaf certificate.
/// If both checks pass, returns any items up to the leaf that are
/// expiring within the given number of days (excludes shorter validity periods).
pub fn et_bundle_pre_issuance_check<R: Role>(
    et_bundle: TokenBundle<ExemptionTokenGroup>,
    expiring_within_days: i64,
) -> Result<Option<ExpiryWarning>, EtBundlePreIssuanceError> {
    if et_bundle.token.try_public_key().is_none() {
        return Err(EtBundlePreIssuanceError::NoKey);
    }

    if let Err(e) = et_bundle.path_to_leaf() {
        let invalid_items: Vec<_> = e.invalid_items.into_iter().map(|ci| ci.into()).collect();
        return Err(EtBundlePreIssuanceError::Chain(invalid_items));
    }

    Ok(et_bundle.check_for_expiry_warning(expiring_within_days))
}

pub fn et_bundle_and_key_pre_issuance_check<R: Role>(
    et_bundle: TokenBundle<ExemptionTokenGroup>,
    key_file_contents: &str,
    passphrase: &str,
) -> Result<(), EtBundlePreIssuanceError> {
    let key = KeyPair::load_key(key_file_contents, passphrase)?;
    et_bundle.token.load_key(key)?;
    Ok(())
}

/// Checks whether the child exemption token request is issuable by the parent exemption token.
/// Does not check that the token/chain is valid or even that the exemption token has an associated key.
pub fn child_etr_pre_issuance_check(
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
    /// The cert is invalid. We aren't checking further up the chain.
    InvalidCert(Box<ChainItemDigestValidationError>),
    IncorrectPassword,
    /// Either they have messed with their keyfile contents or we have broken compatibility.
    CouldNotParseKey,
    /// The key does not match the cert.
    KeyMismatch,
}

#[derive(Serialize)]
// tsgen
pub enum EtBundlePreIssuanceError {
    /// User is attempting to subset with an exemption token with no associated key
    NoKey,
    /// The exemption token and/or leaf cert is invalid
    Chain(Vec<ChainItemDigestValidationError>),
    IncorrectPassword,
    /// Either they have messed with their keyfile contents or we have broken compatibility.
    CouldNotParseKey,
    /// The key does not match the token.
    KeyMismatch,
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

impl From<EtLoadKeyError> for EtBundlePreIssuanceError {
    fn from(e: EtLoadKeyError) -> Self {
        match e {
            EtLoadKeyError::Mismatch(_) => EtBundlePreIssuanceError::KeyMismatch,
            EtLoadKeyError::NoAssociatedKey => EtBundlePreIssuanceError::NoKey,
        }
    }
}

impl From<KeyLoadError> for EtBundlePreIssuanceError {
    fn from(e: KeyLoadError) -> Self {
        match e {
            KeyLoadError::Decrypt(_) => EtBundlePreIssuanceError::IncorrectPassword,
            KeyLoadError::Decode(_) => EtBundlePreIssuanceError::CouldNotParseKey,
        }
    }
}
