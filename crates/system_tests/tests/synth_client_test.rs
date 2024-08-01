#![cfg(feature = "run_system_tests")]
// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;
use std::time::Instant;
use std::{assert_eq, matches};
use std::{sync::Once, time::Duration};

use certificates::file::{load_certificate_bundle_from_file, load_keypair_from_file};
use certificates::test_helpers::{
    create_et_bundle_from_leaf_bundle, create_et_bundle_with_exemptions, create_exemptions,
    BreakableSignature,
};
use once_cell::sync::Lazy;

use certificates::{
    CertificateBundle, Exemption, ExemptionTokenGroup, GenbankId, KeyPair, Organism, Sequence,
    SequenceIdentifier, TokenBundle,
};
use pipeline_bridge::Tag;
use reqwest::StatusCode;
use shared_types::et::WithOtps;
use synthclient::api::{
    ApiError, ApiResponse, ApiWarning, CheckFastaRequest, DebugInfo, RequestCommon,
    SynthesisPermission,
};

const ENDPOINT: &str = "http://localhost:80";

static INIT: Once = Once::new();

pub fn initialize() {
    INIT.call_once(|| {
        retry_until_timeout(
            || {
                let resp = reqwest::blocking::get(format!("{}/version", ENDPOINT))?;
                anyhow::ensure!(resp.status() == 200, "endpoint is not ready");
                println!("Endpoint is ready!");
                Ok(())
            },
            30,
        )
        .unwrap();
    });
}

static TEST_LEAF_BUNDLE: Lazy<(CertificateBundle<Exemption>, KeyPair)> = Lazy::new(|| {
    let certs_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test/certs");
    let leaf_bundle_path = certs_dir.join("exemption-leaf.cert");
    let leaf_key_path = certs_dir.join("exemption-leaf.priv");
    let passphrase_path = certs_dir.join("exemption-leaf.passphrase");

    let leaf_bundle = load_certificate_bundle_from_file(&leaf_bundle_path).unwrap();
    let passphrase = std::fs::read_to_string(passphrase_path).unwrap();
    let leaf_key = load_keypair_from_file(&leaf_key_path, passphrase.trim()).unwrap();
    (leaf_bundle, leaf_key)
});

macro_rules! assert_error {
    ($response:expr, $pat:pat, $addl_str:expr) => {
        let err = $response.errors.get(0).unwrap();

        if !matches!(err, $pat) {
            panic!(
                "error did not match pattern: expected {}, got {:?}",
                stringify!($pat),
                err
            );
        }

        assert!(
            err.additional_info().contains($addl_str),
            "additional info did not contain {}: got {:?}",
            $addl_str,
            err
        );
    };
}

fn assert_all_records_are_matched(response: &ApiResponse, is_match_expected: bool) {
    assert!(
        response
            .hits_by_record
            .iter()
            .all(|record| record.hits_by_hazard.is_empty() != is_match_expected),
        "Not all records were {} in response {:?}",
        is_match_expected,
        response
    );
}

fn construct_request(fasta: &str) -> CheckFastaRequest {
    CheckFastaRequest {
        fasta: String::from(fasta),
        common: RequestCommon {
            region: synthclient::api::Region::All,
            provider_reference: None,
            ets: vec![],
        },
    }
}

fn retry_until_timeout(f: fn() -> anyhow::Result<()>, timeout: u64) -> anyhow::Result<()> {
    // there is probably a better timeout function
    let start = Instant::now();
    loop {
        match f() {
            Ok(_) => {
                return Ok(());
            }
            Err(err) => {
                if start.elapsed().as_secs() >= timeout {
                    return Err(err);
                }
            }
        }
    }
}

fn test_screen_error(fasta: &str, status: u16, check_err: impl FnOnce(ApiResponse)) {
    initialize();

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request(fasta))
        .send()
        .unwrap();

    assert_eq!(resp.status(), status, "status should be 400 (Bad Request)");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Denied,
        "permission should have been denied: {:?}",
        answer
    );

    check_err(answer);
}

#[test]
fn test_404() {
    initialize();
    let resp = reqwest::blocking::get(format!("{}/foo", ENDPOINT)).unwrap();
    assert_eq!(resp.status(), 404, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Denied,
        "permission should have been denied: {:?}",
        answer
    );
}

#[test]
fn test_screen_invalid_fasta() {
    test_screen_error("foo", 400, |err| {
        assert_error!(err, ApiError::InvalidInput(_), "bad nucleotide: 'f'");
    });
    test_screen_error("🍕", 400, |err| {
        assert_error!(err, ApiError::InvalidInput(_), "non-ascii byte");
    });
}

#[test]
fn test_screen_fasta_empty() {
    test_screen_error(">empty\n", 400, |err| {
        assert_error!(
            err,
            ApiError::InvalidInput(_),
            "No sequences were specified"
        );
    });
}

#[test]
fn test_screen_fasta_too_small() {
    initialize();

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request(">small\nAGCAG"))
        .send()
        .unwrap();

    assert_eq!(resp.status(), 200, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Granted,
        "permission should have been granted: {:?}",
        answer
    );
    assert_eq!(answer.warnings, vec![ApiWarning::too_short()]);
}

const HAZARD_SEQ: &str = "CTTCGCGGGATGAGTGTTTTGCCATCTAATAAGTCCAACATTAATTACGGTGCATCAGGC";
const HAZARD_NAME: &str = "Minimal organism";
const HAZARD_AN: &str = "AN1000000.1";

#[test]
fn test_screen_fasta_denied() {
    // this test uses a generated known sequence
    initialize();

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request(HAZARD_SEQ))
        .send()
        .unwrap();

    assert_eq!(resp.status(), 200, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Denied,
        "permission should have been denied: {:?}",
        answer
    );
    assert!(answer.warnings.is_empty());
    assert_all_records_are_matched(&answer, true);

    // check tags

    assert_eq!(answer.hits_by_record.len(), 1);
    // currently returns 331 for number of hits
    // TODO for API, do we want to return tags for every hit? Payload could balloon.
    assert!(!answer.hits_by_record[0].hits_by_hazard.is_empty());
    for hit in &answer.hits_by_record[0].hits_by_hazard {
        assert_eq!(hit.most_likely_organism.tags, vec![Tag::EuropeanUnion,],);
    }
}

fn exemption_bundle_from_test_root(exemptions: Vec<Organism>) -> TokenBundle<ExemptionTokenGroup> {
    let (leaf_bundle, leaf_key) = &*TEST_LEAF_BUNDLE;
    create_et_bundle_from_leaf_bundle(exemptions, leaf_bundle, leaf_key.clone())
}

#[test]
fn test_screen_with_exemption_missing_otp() {
    let et = exemption_bundle_from_test_root(vec![]);
    let et_with_otp = WithOtps {
        et: et.to_file_contents().unwrap(),
        requestor_otp: "".to_owned(),
        issuer_otp: None,
    };

    test_screen_with_exemptions(
        et_with_otp,
        SynthesisPermission::Denied,
        StatusCode::INTERNAL_SERVER_ERROR,
        None,
    );
}

#[test]
fn test_wrong_exemption_token_root() {
    // Token not derived from test root
    let (et, _) = create_et_bundle_with_exemptions(vec![]);
    let et_with_otp = WithOtps {
        et: et.to_file_contents().unwrap(),
        requestor_otp: "cccjgjgkhcbbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb".to_owned(),
        issuer_otp: None,
    };

    test_screen_with_exemptions(
        et_with_otp,
        SynthesisPermission::Denied,
        StatusCode::INTERNAL_SERVER_ERROR,
        Some(
            "the exemption token provided does not originate from the expected root certificate"
                .to_owned(),
        ),
    );
}

#[test]
fn test_invalid_exemption_token_chain() {
    let mut et = exemption_bundle_from_test_root(vec![]);
    et.token.break_signature();

    let et_with_otp = WithOtps {
        et: et.to_file_contents().unwrap(),
        requestor_otp: "cccjgjgkhcbbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb".to_owned(),
        issuer_otp: None,
    };

    test_screen_with_exemptions(
        et_with_otp,
        SynthesisPermission::Denied,
        StatusCode::BAD_REQUEST,
        Some("the following items in the exemption token file are invalid: the exemption token belonging \
        to 'some researcher, email@example.com' is not valid due to signature verification failure".to_owned()),
    );
}

#[test]
fn test_screen_fasta_irrelevant_et_denied() {
    let et = exemption_bundle_from_test_root(create_exemptions());
    let et_with_otp = WithOtps {
        et: et.to_file_contents().unwrap(),
        requestor_otp: "cccjgjgkhcbbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb".to_owned(),
        issuer_otp: None,
    };
    test_screen_with_exemptions(
        et_with_otp,
        SynthesisPermission::Denied,
        StatusCode::OK,
        None,
    );
}

#[test]
fn test_screen_fasta_an_exemption() {
    let et = exemption_bundle_from_test_root(vec![Organism::new(
        "Some organism",
        vec![SequenceIdentifier::Id(
            GenbankId::try_new(HAZARD_AN).unwrap(),
        )],
    )]);

    let et_with_otp = WithOtps {
        et: et.to_file_contents().unwrap(),
        requestor_otp: "cccjgjgkhcbbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb".to_owned(),
        issuer_otp: None,
    };

    test_screen_with_exemptions(
        et_with_otp,
        SynthesisPermission::Granted,
        StatusCode::OK,
        None,
    );
}

#[test]
fn test_screen_fasta_name_exemption() {
    let et = exemption_bundle_from_test_root(vec![Organism::new(
        HAZARD_NAME,
        vec![SequenceIdentifier::Id(GenbankId::try_new("12345").unwrap())],
    )]);

    let et_with_otp = WithOtps {
        et: et.to_file_contents().unwrap(),
        requestor_otp: "cccjgjgkhcbbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb".to_owned(),
        issuer_otp: None,
    };

    test_screen_with_exemptions(
        et_with_otp,
        SynthesisPermission::Granted,
        StatusCode::OK,
        None,
    );
}

#[test]
fn test_screen_fasta_hash_exemption() {
    let et = exemption_bundle_from_test_root(vec![Organism::new(
        "Some organism",
        vec![SequenceIdentifier::Dna(
            Sequence::try_new(HAZARD_SEQ).unwrap(),
        )],
    )]);

    let et_with_otp = WithOtps {
        et: et.to_file_contents().unwrap(),
        requestor_otp: "cccjgjgkhcbbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb".to_owned(),
        issuer_otp: None,
    };

    test_screen_with_exemptions(
        et_with_otp,
        SynthesisPermission::Granted,
        StatusCode::OK,
        None,
    );
}

#[test]
fn test_screen_ambiguous_permuted_fasta_denied() {
    // this test uses a generated known sequence
    initialize();

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request(
            // Same as the test_screen_fasta_denied DNA, but reversed and
            // permuted through ATCG -> GTAC with a few ambiguities sprinkled in
            "AANACCGATGAATCCHGTTGGTTGAKRAATCGGTGGTATGAACBTATCTCGCTGCVHACATTAN",
        ))
        .timeout(Duration::from_secs(90))
        .send()
        .unwrap();

    assert_eq!(resp.status(), 200, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Denied,
        "permission should have been denied: {:?}",
        answer
    );
    assert!(answer.warnings.is_empty());
    assert_all_records_are_matched(&answer, true);

    // check tags

    assert_eq!(answer.hits_by_record.len(), 1);
    // currently returns 331 for number of hits
    // TODO for API, do we want to return tags for every hit? Payload could balloon.
    assert!(!answer.hits_by_record[0].hits_by_hazard.is_empty());
    for hit in &answer.hits_by_record[0].hits_by_hazard {
        assert_eq!(hit.most_likely_organism.tags, vec![Tag::EuropeanUnion,],);
    }
}

#[test]
fn test_screen_fasta_granted() {
    initialize();

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        .send()
        .unwrap();

    assert_eq!(resp.status(), 200, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Granted,
        "permission should have been granted: {:?}",
        answer
    );
    assert!(answer.warnings.is_empty());

    assert_all_records_are_matched(&answer, false);
}

#[test]
fn test_screen_ambiguous_fasta_granted() {
    initialize();

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request("AAAAAAAAAAAAAAANAAAAAAAAAAAAAAAAAAAAAABDWAAAAAAAAAAAAAAAAASAAAAAAAAAAAAAAYAAAAAAAAAAAAANAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAA"))
        .timeout(Duration::from_secs(90))
        .send()
        .unwrap();

    assert_eq!(resp.status(), 200, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Granted,
        "permission should have been granted: {:?}",
        answer
    );
    assert!(answer.warnings.is_empty());

    assert_all_records_are_matched(&answer, false);
}

#[test]
fn test_screen_too_ambiguous() {
    initialize();

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request(
            "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN",
        ))
        .timeout(Duration::from_secs(90))
        .send()
        .unwrap();

    assert_eq!(resp.status(), 200, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Granted,
        "permission should have been granted: {:?}",
        answer
    );
    assert_eq!(answer.warnings, vec![ApiWarning::too_ambiguous()]);

    assert_all_records_are_matched(&answer, false);
}

#[test]
fn test_screen_debug() {
    // this test uses a generated known sequence
    initialize();
    let client = reqwest::blocking::Client::new();

    // test without debug info
    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request(HAZARD_SEQ))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Denied,
        "permission should have been denied: {:?}",
        answer
    );
    assert!(
        answer.debug_info.is_none(),
        "non-empty debug_info: {answer:?}"
    );

    // test with debug info
    let resp = client
        .post(format!("{}/v1/screen?debug_info", ENDPOINT))
        .json::<CheckFastaRequest>(&construct_request(HAZARD_SEQ))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "bad status code: {resp:?}");
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Denied,
        "permission should have been denied: {:?}",
        answer
    );
    assert!(
        matches!(
            &answer.debug_info,
            Some(DebugInfo { grouped_hits }) if !grouped_hits.is_empty(),
        ),
        "empty debug_info: {answer:?}"
    );
}

fn test_screen_with_exemptions(
    et_with_otp: WithOtps<String>,
    expected_permission: SynthesisPermission,
    expected_status: StatusCode,
    additional_info: Option<String>,
) {
    initialize();
    let client = reqwest::blocking::Client::new();

    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&CheckFastaRequest {
            fasta: String::from(HAZARD_SEQ),
            common: RequestCommon {
                region: synthclient::api::Region::All,
                provider_reference: None,
                ets: vec![et_with_otp],
            },
        })
        .send()
        .unwrap();

    let status = resp.status();
    let answer = resp.json::<ApiResponse>().unwrap();

    assert_eq!(status, expected_status, "bad status code: {answer:?}");
    assert_eq!(
        answer.synthesis_permission, expected_permission,
        "permission should have been {expected_permission:?}: {:?}",
        answer
    );
    assert!(answer.warnings.is_empty());
    if let Some(additional_info) = additional_info {
        assert!(
            answer.errors[0]
                .additional_info()
                .contains(&additional_info),
            "unexpected error: {:?}",
            answer.errors[0]
        );
    }
    assert_all_records_are_matched(&answer, true);
}
