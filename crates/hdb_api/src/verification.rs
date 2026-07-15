// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

use certificates::{PublicKey, Signature, key_traits::SigningKeyLoaded};
use sha3::{Digest, Sha3_256};

use crate::{BaseHdbScreeningResult, HdbScreeningResult, HdbVerification};

/// A verifiable screening verifier, which holds a signer and a history URL
/// to construct `VeriaibleHdbScreeningResult`s`
pub struct Verifier<K> {
    signer: K,
    history_url: String,
}

impl<K> Verifier<K>
where
    K: SigningKeyLoaded,
{
    pub fn new(signer: K, history_url: String) -> Self {
        Self {
            signer,
            history_url,
        }
    }

    pub fn to_verifiable(
        &self,
        result: BaseHdbScreeningResult,
        synthclient_version: String,
        fasta_sha3_256_hex: String,
    ) -> Result<HdbScreeningResult, serde_json::Error> {
        let json = serde_json::to_string(&result)?;

        let signature = self.signer.sign(json.as_bytes()).to_string();
        let public_key = self.signer.public_key().to_string();
        let history = self.history_url.clone();

        let hash = Sha3_256::new()
            .chain_update(&synthclient_version)
            .chain_update(&json)
            .chain_update(&signature)
            .chain_update(&public_key)
            .chain_update(&history)
            .chain_update(&fasta_sha3_256_hex)
            .finalize();
        let sha3_256 = hex::encode(hash.as_slice());

        Ok(HdbScreeningResult {
            base: result,
            verification: Some(HdbVerification {
                synthclient_version,
                result_json: json,
                signature,
                public_key,
                history,
                sha3_256,
                fasta_sha3_256_hex,
            }),
        })
    }
}

/// Check an [HdbVerification].
///
/// This check provides no guarantee of origin, because it uses the public key
/// included along with the signature.
pub fn check_verification(verification: &HdbVerification) -> Result<(), CheckVerificationError> {
    let public_key = PublicKey::from_str(&verification.public_key).map_err(|_| {
        CheckVerificationError::DeserializePublicKeyError {
            public_key: verification.public_key.clone(),
        }
    })?;
    let signature = Signature::from_str(&verification.signature).map_err(|_| {
        CheckVerificationError::DeserializeSignatureError {
            signature: verification.signature.clone(),
        }
    })?;

    let expected_hash = Sha3_256::new()
        .chain_update(&verification.synthclient_version)
        .chain_update(&verification.result_json)
        .chain_update(&verification.signature)
        .chain_update(&verification.public_key)
        .chain_update(&verification.history)
        .chain_update(&verification.fasta_sha3_256_hex)
        .finalize();
    let expected_hash = expected_hash.as_slice();
    let expected_hash_str = hex::encode(expected_hash);
    if expected_hash_str != verification.sha3_256 {
        return Err(CheckVerificationError::HashMismatch {
            expected_hash: expected_hash_str,
            actual_hash: verification.sha3_256.clone(),
        });
    }

    if public_key
        .verify(verification.result_json.as_bytes(), &signature)
        .is_err()
    {
        return Err(CheckVerificationError::SignatureMismatch {
            signature: signature.to_string(),
        });
    }

    Ok(())
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CheckVerificationError {
    #[error("failed to decode public key {public_key:?}")]
    DeserializePublicKeyError { public_key: String },
    #[error("failed to decode signature {signature:?}")]
    DeserializeSignatureError { signature: String },
    #[error("hash mismatch: expected {expected_hash:?}, but got {actual_hash:?}")]
    HashMismatch {
        expected_hash: String,
        actual_hash: String,
    },
    #[error("failed to verify signature {signature:?}")]
    SignatureMismatch { signature: String },
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use certificates::{
        DatabaseToken, DatabaseTokenGroup, KeyAvailable, SigningKeyPair,
        key_traits::CanLoadSigningKey,
    };
    use serde_json::json;

    use super::*;
    use crate::{BaseHdbScreeningResult, HdbVersion};

    /// Test that a `SignableHdbScreeningResult` can be correctly signed and verified.
    #[test]
    fn test_sign_and_verify_roundtrip() {
        let base_result = BaseHdbScreeningResult {
            results: vec![],
            debug_hdb_responses: None,
            provider_reference: Some("reference".to_owned()),
            timestamp: "2024-05-29T12:00:00Z".to_string(),
            hdb_version: HdbVersion {
                server_version: "foo".to_owned(),
                hdb_timestamp: None,
            },
        };

        let verifier = Verifier::new(make_signer(), "http://example.com/history".to_string());
        let synthclient_version = "1.2.3-abcdefa".to_owned();
        let fasta_sha3_256_hex = hex::encode(
            Sha3_256::new()
                .chain_update(r#"{{"fasta":"ACTG"}}"#)
                .finalize(),
        );
        let mut verifiable_result = verifier
            .to_verifiable(base_result, synthclient_version, fasta_sha3_256_hex)
            .unwrap();
        let verification = verifiable_result.verification.as_mut().unwrap();

        check_verification(verification).unwrap();

        // The key is randomized, but we can check the JSON structure of the result:
        verification.signature = "".to_string();
        verification.public_key = "".to_string();
        verification.sha3_256 = "".to_string();
        verification.fasta_sha3_256_hex = "".to_string();
        assert_json_eq!(
            verification,
            json!({
                "result_json": "{\"results\":[],\"debug_hdb_responses\":null,\"provider_reference\":\"reference\",\"timestamp\":\"2024-05-29T12:00:00Z\",\"hdb_version\":{\"server_version\":\"foo\",\"hdb_timestamp\":null}}",
                "synthclient_version": "1.2.3-abcdefa",
                "signature": "",
                "public_key": "",
                "history": "http://example.com/history",
                "fasta_sha3_256_hex": "",
                "sha3_256": ""
            })
        );
    }

    /// Test failure in verification due to an altered hash.
    #[test]
    fn test_verification_failure_hash_mismatch() {
        let base_result = BaseHdbScreeningResult {
            results: vec![],
            debug_hdb_responses: None,
            provider_reference: Some("reference".to_owned()),
            timestamp: "2024-05-29T12:00:00Z".to_string(),
            hdb_version: HdbVersion {
                server_version: "foo".to_owned(),
                hdb_timestamp: None,
            },
        };

        let verifier = Verifier::new(make_signer(), "http://example.com/history".to_string());
        let synthclient_version = "1.2.3-abcdefa".to_owned();
        let fasta_sha3_256_hex = hex::encode(
            Sha3_256::new()
                .chain_update(r#"{{"fasta":"ACTG"}}"#)
                .finalize(),
        );
        let mut verifiable_result = verifier
            .to_verifiable(base_result, synthclient_version, fasta_sha3_256_hex)
            .unwrap();
        let verification = verifiable_result.verification.as_mut().unwrap();
        verification.result_json.push(' ');

        let err = check_verification(verification).unwrap_err();
        assert!(
            matches!(err, CheckVerificationError::HashMismatch { .. }),
            "expected HashMismatch, got {err} ({err:?})"
        );
    }

    /// Test failure in verification due to an incorrect signature.
    #[test]
    fn test_verification_failure_signature_mismatch() {
        let base_result = BaseHdbScreeningResult {
            results: vec![],
            debug_hdb_responses: None,
            provider_reference: Some("reference".to_owned()),
            timestamp: "2024-05-29T12:00:00Z".to_string(),
            hdb_version: HdbVersion {
                server_version: "foo".to_owned(),
                hdb_timestamp: None,
            },
        };

        let verifier = Verifier::new(make_signer(), "http://example.com/history".to_string());
        let synthclient_version = "1.2.3-abcdefa".to_owned();
        let fasta_sha3_256_hex = hex::encode(
            Sha3_256::new()
                .chain_update(r#"{{"fasta":"ACTG"}}"#)
                .finalize(),
        );
        let mut verifiable_result = verifier
            .to_verifiable(base_result, synthclient_version, fasta_sha3_256_hex)
            .unwrap();
        let verification = verifiable_result.verification.as_mut().unwrap();
        verification.signature = "0".repeat(128);

        // Fix up the hash so we don't get a HashMismatch error.
        let hash = Sha3_256::new()
            .chain_update(&verification.synthclient_version)
            .chain_update(&verification.result_json)
            .chain_update(&verification.signature)
            .chain_update(&verification.public_key)
            .chain_update(&verification.history)
            .chain_update(&verification.fasta_sha3_256_hex)
            .finalize();
        verification.sha3_256 = hex::encode(hash.as_slice());

        let err = check_verification(verification).unwrap_err();
        assert!(
            matches!(err, CheckVerificationError::SignatureMismatch { .. }),
            "expected SignatureMismatch, got {err} ({err:?})"
        );
    }

    /// Test failure in verification due to an incorrect public key.
    #[test]
    fn test_verification_failure_public_key_error() {
        let base_result = BaseHdbScreeningResult {
            results: vec![],
            debug_hdb_responses: None,
            provider_reference: Some("reference".to_owned()),
            timestamp: "2024-05-29T12:00:00Z".to_string(),
            hdb_version: HdbVersion {
                server_version: "foo".to_owned(),
                hdb_timestamp: None,
            },
        };

        let verifier = Verifier::new(make_signer(), "http://example.com/history".to_string());
        let synthclient_version = "1.2.3-abcdefa".to_owned();
        let fasta_sha3_256_hex = hex::encode(
            Sha3_256::new()
                .chain_update(r#"{{"fasta":"ACTG"}}"#)
                .finalize(),
        );
        let mut verifiable_result = verifier
            .to_verifiable(base_result, synthclient_version, fasta_sha3_256_hex)
            .unwrap();
        let verification = verifiable_result.verification.as_mut().unwrap();
        verification.public_key = "invalid_public_key".to_string();

        let err = check_verification(verification).unwrap_err();
        assert!(
            matches!(
                err,
                CheckVerificationError::DeserializePublicKeyError { .. }
            ),
            "expected DeserializePublicKeyError, got {err} ({err:?})"
        );
    }

    fn make_signer() -> DatabaseToken<KeyAvailable> {
        let keypair = SigningKeyPair::new_random();
        let (token, _) = certificates::test_helpers::create_token_bundle::<DatabaseTokenGroup, _, _>(
            || certificates::DatabaseTokenRequest::v1_token_request(keypair.public_key()),
            |cert, req| cert.issue_database_token(req, certificates::Expiration::default()),
        );
        token.token.load_key(keypair).unwrap()
    }
}
