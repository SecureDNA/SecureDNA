// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)]

use std::collections::HashSet;

use certificates::{
    Authenticator, ExemptionListTokenGroup, TokenBundle, TokenBundleError, YubikeyId,
};
use hdb::{Entry, Exemptions};
use thiserror::Error;
use yubico::{config::Config, verify_async, yubicoerror::YubicoError};

#[derive(Debug)]
/// Specifies where a list of 2FA authenticators orginiates from.
pub enum AuthenticatorSource {
    /// The authenticators were added during ELTR creation by the requestor.
    Requestor,
    /// The authenticators were added during ELT approval by the issuer.
    Issuer,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Error decoding exemption list token: {0}")]
    DecodeError(#[from] TokenBundleError),
    #[error("Exemption list token has no 2FA authenticators")]
    EltMissing2fa,
    #[error("All {0:?} authenticators failed: {1:?}")]
    AuthFailed(AuthenticatorSource, Vec<AuthenticatorError>),
}

#[derive(Debug, Error)]
pub enum AuthenticatorError {
    #[error("Yubico: {0}")]
    Yubico(YubicoValidationError),
}

#[derive(Debug, Error)]
pub enum YubicoValidationError {
    #[error("synthclient was not configured with Yubico API credentials")]
    Unsupported,
    #[error("Synthesis request is missing a Yubico OTP")]
    NoOtpProvided,
    #[error("OTP does not match the Yubikey ID")]
    OtpMismatch,
    #[error("Validation failed: {0}")]
    Failed(#[from] YubicoError),
}

pub trait Validator {
    /// Validate a Yubico (Yubikey) OTP.
    async fn validate_yubico(
        &self,
        yubikey_id: &YubikeyId,
        yubico_otp: &Option<String>,
    ) -> Result<(), YubicoValidationError>;

    /// Validate all the `authenticators` in turn using the provided credentials.
    ///
    /// - If any of them succeed, return `Ok(())`.
    /// - If they all fail, return
    ///   `Err(ValidationError::AuthFailed(authenticator_source, failures))`.
    async fn validate_one_of(
        &self,
        authenticator_source: AuthenticatorSource,
        authenticators: &[Authenticator],
        yubico_otp: &Option<String>,
    ) -> Result<(), ValidationError> {
        let mut failures: Vec<AuthenticatorError> = vec![];
        for auth in authenticators {
            match auth {
                Authenticator::Yubikey(id) => match self.validate_yubico(id, yubico_otp).await {
                    Ok(()) => return Ok(()),
                    Err(e) => failures.push(AuthenticatorError::Yubico(e)),
                },
            }
        }
        Err(ValidationError::AuthFailed(authenticator_source, failures))
    }

    /// Validate an ELT TokenBundle:
    ///
    /// - It must have at least one non-empty list of authenticators.
    /// - If there are requestor-sourced auths, one of them must validate.
    /// - If there are issuer-sourced auths, one of them must validate.
    async fn validate_elt(
        &self,
        elt_bundle: &TokenBundle<ExemptionListTokenGroup>,
        yubico_otp: &Option<String>,
    ) -> Result<(), ValidationError> {
        let request_auths = elt_bundle.token.requestor_auth_devices();
        let issuer_auths = elt_bundle.token.issuer_auth_devices();

        if request_auths.is_empty() && issuer_auths.is_empty() {
            return Err(ValidationError::EltMissing2fa);
        }

        for (source, auths) in [
            (AuthenticatorSource::Requestor, request_auths),
            (AuthenticatorSource::Issuer, issuer_auths),
        ] {
            if !auths.is_empty() {
                self.validate_one_of(source, auths, yubico_otp).await?;
            }
        }

        Ok(())
    }
}

/// A Validator that validates authenticators by talking to the network
/// (YubiCloud).
pub struct NetworkingValidator {
    pub yubico_api_client_id: Option<String>,
    pub yubico_api_secret_key: Option<String>,
}

impl Validator for NetworkingValidator {
    async fn validate_yubico(
        &self,
        yubikey_id: &YubikeyId,
        yubico_otp: &Option<String>,
    ) -> Result<(), YubicoValidationError> {
        match (
            &self.yubico_api_client_id,
            &self.yubico_api_secret_key,
            yubico_otp,
        ) {
            (Some(id), Some(key), Some(otp)) => {
                // Sanity check: the OTP they submitted should start with the
                // 12-character Yubikey ID in the ELT.
                if !otp.starts_with(&yubikey_id.to_string()) {
                    return Err(YubicoValidationError::OtpMismatch);
                }
                let config = Config::default().set_client_id(id).set_key(key);
                verify_async(otp, config).await?;
                Ok(())
            }
            (_, _, Some(_otp)) => Err(YubicoValidationError::Unsupported),
            _ => Err(YubicoValidationError::NoOtpProvided),
        }
    }
}

pub async fn exemptions_from_yubico_otp(
    token_bundles: Vec<TokenBundle<ExemptionListTokenGroup>>,
    hashes: HashSet<[u8; Entry::HASH_LENGTH]>,
    validator: &(impl Validator + std::marker::Sync),
    yubico_otp: &Option<String>,
) -> Result<Exemptions, ValidationError> {
    for bundle in &token_bundles {
        validator.validate_elt(bundle, yubico_otp).await?;
    }
    Ok(Exemptions::new_unchecked(token_bundles, hashes))
}
