// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use certificates::{
    ChainTraversal, ChainValidationError, Exemption, FixedClock, Infrastructure, Issued, PublicKey,
    Signature, SignatureVerificationError, TokenBundle, TokenBundleError, ValidationError,
    key::error::SignatureParseError, key_traits::HasAssociatedSigningKey,
};
use doprf_client::error::DoprfError;
use hdb_api::{
    BaseHdbScreeningResult, HdbScreeningResult, HdbVerification,
    verification::{CheckVerificationError, check_verification},
};
use quickdna::{FastaParseError, Located, NucleotideAmbiguous, TranslationError};
use rotation::{RotationParseError, parse_rotations};
use sha3::{Digest, Sha3_256};
use synthclient::{
    api::{ApiResponse, CheckFastaRequest},
    parsefasta::parse_fasta,
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Iso8601};

use fetch::HistoryFetcher;
use timeline::Timeline;

pub mod fetch;
pub mod rotation;
pub mod timeline;

#[derive(Debug, Error)]
pub enum CheckTokenError {
    #[error("This token could not be downloaded: {0}")]
    FetchFailed(#[from] anyhow::Error),
    #[error("This token is invalid: {0}")]
    TokenInvalid(#[from] ValidationError),
    #[error("This token's chain is invalid: {0}")]
    TokenChainInvalid(#[from] ChainValidationError<Infrastructure>),
    #[error("Verification failed: {0}")]
    VerificationFailed(#[from] SignatureVerificationError),
}

fn list_check_token_errors(errors: &[(i64, CheckTokenError)]) -> String {
    let mut result = String::new();
    for (t, e) in errors {
        result += &format!("\n* {t}: {e}");
    }
    result
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error(
        "The request body is invalid: {0}. It should be a JSON object in the same format as accepted by the /screen endpoint."
    )]
    BadRequestJson(serde_json::Error),
    #[error(
        "The response body is invalid: {0}. It should be a JSON object returned by synthclient from the /screen endpoint."
    )]
    BadResponseJson(serde_json::Error),
    #[error("The response body's `response_json` field is invalid: {0}.")]
    BadInnerResponseJson(serde_json::Error),
    #[error("The request body's `ets` field is invalid: {0}.")]
    BadEts(#[from] TokenBundleError<Exemption>),
    #[error(
        "This request did not have verifiable screening enabled, and so it cannot be verified."
    )]
    NotVerifiable,
    #[error("The request body does not contain a valid FASTA string: {0}")]
    InvalidSequence(#[from] Located<FastaParseError<TranslationError>>),
    #[error("Verification failed: {0}")]
    InHdb(#[from] CheckVerificationError),
    #[error("Could not recreate synthclient response from HDB response: {0}")]
    RecreationFailed(#[from] DoprfError),
    #[error(
        "Recreating synthclient response from HDB response yielded a different result: original = {0:?}, recreated = {1:?}"
    )]
    RecreationMismatch(Box<ApiResponse>, Box<ApiResponse>),
    #[error("Could not download history: {0}")]
    FetchHistoryFailed(anyhow::Error),
    #[error("The verifier token history could not be parsed: {0}")]
    BadHistory(#[from] RotationParseError),
    #[error("The HDB response timestamp is invalid: {0}")]
    InvalidHdbTimestamp(time::error::Parse),
    #[error(
        "The public key does not match the history. The verifiable result contains {0:?}, but the history says the valid keys at the time of this result were {1:?}."
    )]
    InvalidPublicKey(String, Vec<String>),
    #[error("The signature in the verifiable screening result cannot be parsed.")]
    SignatureParseError(#[from] SignatureParseError),
    #[error("None of the candidate tokens could verify this result:\n{}", list_check_token_errors(.0))]
    BadTokens(Vec<(i64, CheckTokenError)>),
}

async fn check_token(
    history_fetcher: &impl HistoryFetcher,
    time: i64,
    history_url: &str,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CheckTokenError> {
    let token = history_fetcher.fetch_token(history_url, time).await?;
    let clock = FixedClock {
        unix_timestamp: time,
    };
    token.token.check_signature_and_expiry(&clock)?;

    #[cfg(not(test))]
    let contents = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../certs/infrastructure-root.pub"
    ));

    #[cfg(test)]
    let contents = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/certs/infrastructure-root.pub"
    ));

    // It's a bit inefficient to load this every time this function runs, but
    // it's not a big deal.
    let root_public_key =
        PublicKey::from_file_contents(contents).expect("Root public key could not be read");

    token.validate_path_to_issuers(&[root_public_key], None, &clock)?;
    token.token.public_key().verify(message, signature)?;
    Ok(())
}

/// Given a list of token names, download verifier tokens from the history until
/// we find one that matches and verifies the response.
///
/// If no token works, return a [VerificationError::BadTokens] collecting all
/// the errors.
async fn check_tokens(
    history_fetcher: &impl HistoryFetcher,
    times: &[i64],
    history_url: &str,
    message: &[u8],
    signature: &Signature,
) -> Result<(), VerificationError> {
    let mut failures: Vec<(i64, CheckTokenError)> = vec![];
    for time in times {
        match check_token(history_fetcher, *time, history_url, message, signature).await {
            Ok(()) => return Ok(()),
            Err(e) => failures.push((*time, e)),
        }
    }
    Err(VerificationError::BadTokens(failures))
}

/// Verify a verifiable screening request-response pair.
///
/// 1. Parse everything.
/// 2. Hash the request JSON.
/// 3. Check that the HDB response signature matches this hash.
/// 4. Recreate the rest of the synthclient response from the HDB response,
///    using the DNA from the request.
/// 5. Check that the recreated result matches the original response.
/// 6. Fetch `history` from GitHub and figure out the current rotation at the
///    time of screening.
/// 7. Check that this rotation matches the public key in the response.
///
/// When checking the public key, `rotation_grace_period_seconds` will be used
/// to provide some leeway around the times tokens got rotated. (When rotating
/// from token 1 to token 2, token 1 will be valid for
/// `rotation_grace_period_seconds` more seconds after the last acknowledgement
/// of token 2.)
pub async fn verify(
    request_json: &str,
    response_json: &str,
    rotation_grace_period_seconds: i64,
    history_fetcher: &impl HistoryFetcher,
) -> Result<(), VerificationError> {
    let (request, response): (CheckFastaRequest, ApiResponse) = (
        serde_json::from_str(request_json).map_err(VerificationError::BadRequestJson)?,
        serde_json::from_str(response_json).map_err(VerificationError::BadResponseJson)?,
    );

    let Some(ref verifiable) = response.verifiable else {
        return Err(VerificationError::NotVerifiable);
    };

    let hdb_response: BaseHdbScreeningResult = serde_json::from_str(&verifiable.response_json)
        .map_err(VerificationError::BadInnerResponseJson)?;

    let fasta_file = parse_fasta::<NucleotideAmbiguous>(&request.fasta)?;

    let ets = request
        .common
        .ets
        .iter()
        .map(|et| et.clone().try_map(TokenBundle::from_file_contents))
        .collect::<Result<Vec<_>, _>>()
        .map_err(VerificationError::BadEts)?;

    let fasta_sha3_256_hex = hex::encode(Sha3_256::digest(request_json));

    let hdb_verification = HdbVerification {
        synthclient_version: verifiable.synthclient_version.clone(),
        result_json: verifiable.response_json.clone(),
        signature: verifiable.signature.clone(),
        public_key: verifiable.public_key.clone(),
        history: verifiable.history.clone(),
        fasta_sha3_256_hex: fasta_sha3_256_hex.clone(),
        sha3_256: verifiable.sha3_256.clone(),
    };

    check_verification(&hdb_verification)?;

    let hdb_time = OffsetDateTime::parse(&hdb_response.timestamp, &Iso8601::DEFAULT)
        .map_err(VerificationError::InvalidHdbTimestamp)?;

    let mut recreated = ApiResponse::from_hdb_result(
        HdbScreeningResult {
            base: hdb_response,
            verification: Some(hdb_verification),
        },
        &fasta_file.records,
        &doprf_client::ScreeningParams {
            // It's okay to load the test certs here as a set of "dummy certs",
            // because those are embedded in the binary, and we won't actually
            // talk to the keyservers or database. In the worst case
            // `from_hdb_result` generates a warning about these certs being
            // expired, but we will ignore warnings.
            certs: Arc::new(scep_client_helpers::ClientCerts::load_test_certs()),
            include_debug_info: response.debug_info.is_some(),
            verifiable_screening: true,
            region: request.common.region.into(),
            ets,
            fasta_sha3_256_hex,
            synthclient_version: verifiable.synthclient_version.clone(),
        },
        response.provider_reference.clone(),
    )?;

    // Ignore warnings when comparing recreation to source. The cert expiry
    // warning is one reason; another involves a spurious warning about order
    // ambiguity that we want to ignore as well because we don't have access to
    // the exact HTDV used in this order.
    recreated.warnings = response.warnings.clone();
    if response != recreated {
        return Err(VerificationError::RecreationMismatch(
            response.into(),
            recreated.into(),
        ));
    }

    let update_log = history_fetcher
        .fetch_update_log(&verifiable.history)
        .await
        .map_err(VerificationError::FetchHistoryFailed)?;

    let rotations = parse_rotations(&update_log)?;
    let candidates = Timeline::from_rotations(&rotations, rotation_grace_period_seconds)
        .valid_tokens(hdb_time.unix_timestamp());

    let message = verifiable.response_json.as_bytes();
    let signature: Signature = verifiable.signature.parse()?;
    check_tokens(
        history_fetcher,
        &candidates,
        &verifiable.history,
        message,
        &signature,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use certificates::{TokenBundle, VerifierTokenGroup};

    use crate::{VerificationError, fetch::HistoryFetcher, verify};

    enum TestHistoryFetcher {
        Normal,
        FetchHistoryFails,
        HistoryIsBad,
        HistoryIsFuturistic,
    }

    impl HistoryFetcher for TestHistoryFetcher {
        async fn fetch_update_log(&self, _history_url: &str) -> anyhow::Result<String> {
            match self {
                TestHistoryFetcher::FetchHistoryFails => anyhow::bail!("see ya"),
                TestHistoryFetcher::HistoryIsBad => Ok("weird file".to_owned()),
                TestHistoryFetcher::HistoryIsFuturistic => {
                    Ok("9999999999\tdb1.localhost.securedna.org\t9999999999".to_owned())
                }
                _ => Ok("1746443766\tdb1.localhost.securedna.org\t1746443766".to_owned()),
            }
        }

        async fn fetch_token(
            &self,
            _history_url: &str,
            rotation: i64,
        ) -> anyhow::Result<TokenBundle<VerifierTokenGroup>> {
            assert_eq!(rotation, 1746443766);
            let contents = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../test/certs/verifier-token.vt"
            ));
            Ok(TokenBundle::from_file_contents(contents)?)
        }
    }

    #[tokio::test]
    async fn verify_readme_screening() {
        let request = include_str!("test/verify_readme_screening/request.json");
        let response = include_str!("test/verify_readme_screening/response.json");

        verify(request, response, 86400, &TestHistoryFetcher::Normal)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_readme_screening_errors() {
        let request = include_str!("test/verify_readme_screening/request.json");
        let response = include_str!("test/verify_readme_screening/response.json");

        let error = verify("asdf", response, 86400, &TestHistoryFetcher::Normal).await;
        let Err(VerificationError::BadRequestJson(_)) = error else {
            panic!("expected BadRequestJson, got {error:?}");
        };

        let error = verify(request, "asdf", 86400, &TestHistoryFetcher::Normal).await;
        let Err(VerificationError::BadResponseJson(_)) = error else {
            panic!("expected BadResponseJson, got {error:?}");
        };

        let error = verify(
            request,
            &response.replace("hdb_timestamp", "\\\""),
            86400,
            &TestHistoryFetcher::Normal,
        )
        .await;
        let Err(VerificationError::BadInnerResponseJson(_)) = error else {
            panic!("expected BadInnerResponseJson, got {error:?}");
        };

        let error = verify(
            request,
            r#"{"synthesis_permission":"granted"}"#,
            86400,
            &TestHistoryFetcher::Normal,
        )
        .await;
        let Err(VerificationError::NotVerifiable) = error else {
            panic!("expected NotVerifiable, got {error:?}");
        };

        let error = verify(
            &request.replace("CTTC", "!@#$"),
            response,
            86400,
            &TestHistoryFetcher::Normal,
        )
        .await;
        let Err(VerificationError::InvalidSequence(_)) = error else {
            panic!("expected InvalidSequence, got {error:?}");
        };

        let error = verify(
            request,
            &response.replacen("3f14", "0000", 1),
            86400,
            &TestHistoryFetcher::Normal,
        )
        .await;
        let Err(VerificationError::InHdb(_)) = error else {
            panic!("Not InHdb: {error:?}");
        };

        let error = verify(
            request,
            &response.replacen("denied", "granted", 1),
            86400,
            &TestHistoryFetcher::Normal,
        )
        .await;
        let Err(VerificationError::RecreationMismatch(_, _)) = error else {
            panic!("Not RecreationMismatch: {error:?}");
        };

        let error = verify(
            request,
            &response.replacen("denied", "granted", 1),
            86400,
            &TestHistoryFetcher::Normal,
        )
        .await;
        let Err(VerificationError::RecreationMismatch(_, _)) = error else {
            panic!("Not RecreationMismatch: {error:?}");
        };

        let error = verify(
            request,
            response,
            86400,
            &TestHistoryFetcher::FetchHistoryFails,
        )
        .await;
        let Err(VerificationError::FetchHistoryFailed(_)) = error else {
            panic!("Not FetchHistoryFailed: {error:?}");
        };

        let error = verify(request, response, 86400, &TestHistoryFetcher::HistoryIsBad).await;
        let Err(VerificationError::BadHistory(_)) = error else {
            panic!("Not BadHistory: {error:?}");
        };

        let error = verify(
            request,
            response,
            86400,
            &TestHistoryFetcher::HistoryIsFuturistic,
        )
        .await;
        let Err(VerificationError::BadTokens(_)) = error else {
            panic!("Not BadTokens: {error:?}");
        };
    }
}
