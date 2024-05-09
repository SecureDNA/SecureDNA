// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)]

use std::collections::HashSet;

use certificates::{
    Authenticator, ExemptionListTokenGroup, TokenBundle, TokenBundleError, YubikeyId,
};
use hdb::{Entry, Exemptions};

use serde::Serialize;
use thiserror::Error;
use yubico::yubicoerror::YubicoError;

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
    #[error("Totp: {0}")]
    Totp(TotpValidationError),
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

#[derive(Debug, Error)]
pub enum TotpValidationError {
    #[error("Synthesis request is missing a TOTP OTP")]
    NoOtpProvided,
    #[error("Validation failed: {0}")]
    Failed(String),
}

pub trait Validator {
    /// Validate a Yubico (Yubikey) OTP.
    async fn validate_yubico(
        &self,
        yubikey_id: &YubikeyId,
        yubico_otp: &Option<String>,
    ) -> Result<(), YubicoValidationError>;

    /// Validate a TOTP OTP.
    async fn validate_totp(
        &self,
        id: &str,
        otp: &Option<String>,
    ) -> Result<(), TotpValidationError>;

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
        totp_otp: &Option<String>,
    ) -> Result<(), ValidationError> {
        let mut failures: Vec<AuthenticatorError> = vec![];
        for auth in authenticators {
            match auth {
                Authenticator::Yubikey(id) => match self.validate_yubico(id, yubico_otp).await {
                    Ok(()) => return Ok(()),
                    Err(e) => failures.push(AuthenticatorError::Yubico(e)),
                },
                Authenticator::Totp(id) => match self.validate_totp(id, totp_otp).await {
                    Ok(()) => return Ok(()),
                    Err(e) => failures.push(AuthenticatorError::Totp(e)),
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
        totp_otp: &Option<String>,
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
                self.validate_one_of(source, auths, yubico_otp, totp_otp)
                    .await?;
            }
        }

        Ok(())
    }
}

/// A Validator that validates authenticators by talking to the network
/// (YubiCloud).
#[derive(Default)]
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
        let otp = match yubico_otp.as_deref() {
            None | Some("") => return Err(YubicoValidationError::NoOtpProvided),
            Some(otp) => otp,
        };

        let client_id = self.yubico_api_client_id.as_deref();
        let secret_key = self.yubico_api_secret_key.as_deref();
        match (client_id, secret_key) {
            (Some("allow_all"), _) => Ok(()),
            (Some(id), Some(key)) => {
                // Sanity check: the OTP they submitted should start with the
                // 12-character Yubikey ID in the ELT.
                if !otp.starts_with(&yubikey_id.to_string()) {
                    return Err(YubicoValidationError::OtpMismatch);
                }
                let config = yubico::config::Config::default()
                    .set_client_id(id)
                    .set_key(key);
                yubico::verify_async(otp, config).await?;
                Ok(())
            }
            (_, _) => Err(YubicoValidationError::Unsupported),
        }
    }

    async fn validate_totp(
        &self,
        serial: &str,
        pass: &Option<String>,
    ) -> Result<(), TotpValidationError> {
        let Some(pass) = pass else {
            return Err(TotpValidationError::NoOtpProvided);
        };

        // The request format is documented here:
        // https://github.com/SecureDNA/devops/blob/main/bin/pi-token-server/README.md#validating-an-otp
        #[derive(Serialize)]
        struct TokenCheckBody<'a> {
            time: i64,
            serial: &'a str,
            pass: &'a str,
        }

        let client = reqwest::Client::new();
        let url = "https://pi.securedna.org/securedna/token/v1/check";
        let time = time::OffsetDateTime::now_utc().unix_timestamp();
        let body = TokenCheckBody { time, serial, pass };

        let Ok(res) = client.post(url).json(&body).send().await else {
            return Err(TotpValidationError::Failed(
                "validation server could not be reached".to_owned(),
            ));
        };

        use serde_json::value::Value;
        let Ok(json) = res.json::<Value>().await else {
            return Err(TotpValidationError::Failed(
                "response was not valid JSON".to_owned(),
            ));
        };

        // The response format is documented here:
        // https://privacyidea.readthedocs.io/en/latest/modules/api/validate.html
        match json["result"]["value"] {
            Value::Bool(true) => Ok(()),
            Value::Bool(false) => Err(TotpValidationError::Failed("incorrect OTP".to_owned())),
            _ => Err(TotpValidationError::Failed(
                "response JSON format was invalid".to_owned(),
            )),
        }
    }
}

pub async fn exemptions_from_otp(
    token_bundles: Vec<TokenBundle<ExemptionListTokenGroup>>,
    hashes: HashSet<[u8; Entry::HASH_LENGTH]>,
    validator: &(impl Validator + std::marker::Sync),
    yubico_otp: &Option<String>,
    totp_otp: &Option<String>,
) -> Result<Exemptions, ValidationError> {
    for bundle in &token_bundles {
        validator.validate_elt(bundle, yubico_otp, totp_otp).await?;
    }
    Ok(Exemptions::new_unchecked(token_bundles, hashes))
}

#[cfg(test)]
mod tests {
    #[cfg_attr(not(feature = "run_network_tests"), ignore)]
    #[tokio::test]
    async fn test_totp() {
        use serde_json::json;
        let client = reqwest::Client::new();
        let url = "https://pi.securedna.org/securedna/token/v1/token";
        let time = time::OffsetDateTime::now_utc().unix_timestamp();
        let body = json!({ "time": time });

        use serde_json::value::Value;
        let res = client.post(url).json(&body).send().await.unwrap();
        let json = res.json::<Value>().await.unwrap();
        let serial = json["detail"]["serial"].as_str().unwrap();
        let secret = json["detail"]["googleurl"]["value"].as_str().unwrap();
        let secret = secret.split("?secret=").nth(1).unwrap();
        let secret = secret.split('&').next().unwrap();

        use totp_rs::{Algorithm, Secret, TOTP};
        let secret = Secret::Encoded(secret.to_owned()).to_bytes().unwrap();
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret).unwrap();
        let code = totp.generate_current().unwrap();

        use crate::validation::{NetworkingValidator, Validator};
        let validator = NetworkingValidator::default();
        validator.validate_totp(serial, &Some(code)).await.unwrap();
    }
}
