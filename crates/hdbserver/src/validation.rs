// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)]

use std::{collections::HashSet, str::FromStr};

use base64::Engine;
use certificates::{
    revocation::RevocationList, Authenticator, CertificateBundle, ChainTraversal, EncodeError,
    Exemption, ExemptionTokenGroup, PublicKey, Signature, SystemClock, TokenBundle,
    TokenBundleError, YubikeyId,
};
use hdb::{Entry, Exemptions};
use serde::Serialize;
use shared_types::{error::InvalidClientTokenBundle, et::WithOtps};
use thiserror::Error;
use tracing::error;
use yubico::yubicoerror::YubicoError;

#[derive(Debug)]
/// Specifies where a list of 2FA authenticators orginiates from.
pub enum AuthenticatorSource {
    /// The authenticators were added during ETR creation by the requestor.
    Requestor,
    /// The authenticators were added during ET approval by the issuer.
    Issuer,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Error decoding exemption token: {0}")]
    DecodeError(#[from] TokenBundleError<Exemption>),
    #[error("Error converting exemption token to contents: {0}")]
    EncodeError(#[from] EncodeError),
    #[error("Exemption token has no 2FA authenticators")]
    EtMissing2fa,
    #[error("Exemption token has issuer-supplied 2FA authenticators, but no issuer_otp")]
    EtMissingIssuer2fa,
    #[error("All {0:?} authenticators failed: {1:?}")]
    AuthFailed(AuthenticatorSource, Vec<AuthenticatorError>),
    #[error(transparent)]
    Chain(#[from] InvalidClientTokenBundle<Exemption>),
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
        data_to_sign: &[u8],
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
        otp: &Option<String>,
        data_to_sign: &[u8],
    ) -> Result<(), ValidationError> {
        let mut failures: Vec<AuthenticatorError> = vec![];
        for auth in authenticators {
            match auth {
                Authenticator::Yubikey(id) => match self.validate_yubico(id, otp).await {
                    Ok(()) => return Ok(()),
                    Err(e) => failures.push(AuthenticatorError::Yubico(e)),
                },
                Authenticator::Totp(id) => {
                    let mut single_data_to_sign = data_to_sign.to_vec();
                    single_data_to_sign.extend_from_slice(id.as_bytes());
                    if let Some(otp) = otp {
                        single_data_to_sign.extend_from_slice(otp.as_bytes());
                    }
                    match self.validate_totp(id, otp, &single_data_to_sign).await {
                        Ok(()) => return Ok(()),
                        Err(e) => failures.push(AuthenticatorError::Totp(e)),
                    }
                }
            }
        }
        Err(ValidationError::AuthFailed(authenticator_source, failures))
    }

    /// Validate an exemption token bundle:
    ///
    /// - It must have at least one non-empty list of authenticators.
    /// - If there are requestor-sourced auths, one of them must validate.
    /// - If there are issuer-sourced auths, one of them must validate.
    ///
    /// The `data_to_sign` will be signed by the TOTP token server when
    /// validating the OTPs.
    async fn validate_et(
        &self,
        et_bundle: &WithOtps<TokenBundle<ExemptionTokenGroup>>,
        data_to_sign: &[u8],
    ) -> Result<(), ValidationError> {
        let requestor_auths = et_bundle.et.token.requestor_auth_devices();
        let issuer_auths = et_bundle.et.token.issuer_auth_devices();

        if requestor_auths.is_empty() && issuer_auths.is_empty() {
            return Err(ValidationError::EtMissing2fa);
        }

        self.validate_one_of(
            AuthenticatorSource::Requestor,
            requestor_auths,
            &Some(et_bundle.requestor_otp.clone()),
            data_to_sign,
        )
        .await?;

        if !issuer_auths.is_empty() {
            match &et_bundle.issuer_otp {
                Some(otp) => {
                    self.validate_one_of(
                        AuthenticatorSource::Issuer,
                        issuer_auths,
                        &Some(otp.clone()),
                        data_to_sign,
                    )
                    .await?
                }
                None => return Err(ValidationError::EtMissingIssuer2fa),
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
    pub token_server_bundle: CertificateBundle<Exemption>,
    pub totp_access_passphrase: String,
}

impl NetworkingValidator {
    /// Validates that the TOTP certificate bundle chains back to the exemption roots
    pub fn validate_totp_certificate_chain(
        &self,
        exemption_roots: &[PublicKey],
        revocation_list: &RevocationList,
    ) -> Result<(), ValidationError> {
        // Validate the certificate bundle back to exemption roots
        self.token_server_bundle
            .validate_path_to_issuers(exemption_roots, Some(revocation_list), &SystemClock)
            .map_err(|error| InvalidClientTokenBundle {
                error,
                token_kind: certificates::TokenKind::Exemption,
            })?;

        Ok(())
    }
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
                // 12-character Yubikey ID in the ET.
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
        data_to_sign: &[u8],
    ) -> Result<(), TotpValidationError> {
        let Some(pass) = pass else {
            return Err(TotpValidationError::NoOtpProvided);
        };

        #[derive(Serialize)]
        struct TokenCheckBody<'a> {
            time: i64,
            serial: &'a str,
            pass: &'a str,
            data: &'a str,
            access: &'a str,
        }

        // Avoid openssl due to potential getenv/setenv-induced UB.
        let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();

        let url = "https://pi.securedna.org/securedna/token/v1/check";
        let time = time::OffsetDateTime::now_utc().unix_timestamp();
        let b64_data = base64::prelude::BASE64_STANDARD.encode(data_to_sign);
        let body = TokenCheckBody {
            time,
            serial,
            pass,
            data: b64_data.as_str(),
            access: self.totp_access_passphrase.as_str(),
        };

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

        let Value::String(hex_signature) = &json["sdna_signature"] else {
            return Err(TotpValidationError::Failed(
                "No sdna_signature string in response".to_owned(),
            ));
        };

        let signature = Signature::from_str(hex_signature).map_err(|_| {
            error!("MISCONFIGURATION: invalid signature: {hex_signature}");
            TotpValidationError::Failed(format!("Invalid signature: {hex_signature}"))
        })?;

        let public_key = self
            .token_server_bundle
            .get_lead_cert(&SystemClock)
            .map_err(|_| {
                error!("MISCONFIGURATION: no lead cert found");
                TotpValidationError::Failed("No lead cert found".to_owned())
            })?
            .public_key();

        public_key
            .verify(b64_data.as_bytes(), &signature)
            .map_err(|_| {
                error!("MISCONFIGURATION: verification failed: public_key={public_key:?} b64_data={b64_data:?} signature={signature:?}");
                TotpValidationError::Failed("Verification failed".to_owned())
            })?;

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

pub async fn exemptions_after_validation(
    token_bundles: Vec<WithOtps<TokenBundle<ExemptionTokenGroup>>>,
    hashes: HashSet<[u8; Entry::HASH_LENGTH]>,
    validator: &(impl Validator + std::marker::Sync),
    exemptions_roots: &[PublicKey],
    revocation_list: &RevocationList,
    data_to_sign: &[u8],
) -> Result<Exemptions, ValidationError> {
    for bundle in &token_bundles {
        validator.validate_et(bundle, data_to_sign).await?;
        bundle
            .et
            .validate_path_to_issuers(exemptions_roots, Some(revocation_list), &SystemClock)
            .map_err(|error| InvalidClientTokenBundle {
                error,
                token_kind: certificates::TokenKind::Exemption,
            })?;
    }
    Ok(Exemptions::new_unchecked(
        token_bundles.into_iter().map(|bundle| bundle.et).collect(),
        hashes,
    ))
}

#[cfg(test)]
mod tests {
    use crate::validation::{NetworkingValidator, Validator};
    use certificates::{CertificateBundle, Exemption};
    #[cfg_attr(not(feature = "run_network_tests"), ignore)]
    #[tokio::test]
    async fn test_totp() {
        use serde_json::json;
        // Avoid openssl due to potential getenv/setenv-induced UB.
        let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();

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

        let contents = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../certs/TOTP/totp.cert"
        ));

        let token_server_bundle = CertificateBundle::<Exemption>::from_file_contents(contents)
            .expect("TOTP certificate could not be read");

        let data_to_sign = b"message";

        let validator = NetworkingValidator {
            yubico_api_client_id: None,
            yubico_api_secret_key: None,
            token_server_bundle,
            totp_access_passphrase: std::env::var("SECUREDNA_TEST_TOTP_ACCESS_PASSPHRASE").unwrap(),
        };

        validator
            .validate_totp(serial, &Some(code), data_to_sign)
            .await
            .unwrap();
    }
}
