#![cfg(feature = "run_system_tests")]
// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::Instant;
use std::{sync::Once, time::Duration};

use certificates::test_helpers::{create_elt_bundle_with_exemptions, create_exemptions};
use certificates::{GenbankId, Organism, Sequence, SequenceIdentifier};
use pipeline_bridge::Tag;
use synthclient::api::{
    ApiError, ApiResponse, ApiWarning, CheckFastaRequest, RequestCommon, SynthesisPermission,
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
            elt_pem: None,
            otp: None,
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
    assert_eq!(answer.warnings, vec![]);
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

fn test_elt(exemptions: Vec<Organism>, expected_permission: SynthesisPermission) {
    initialize();
    let client = reqwest::blocking::Client::new();
    let (elt, _) = create_elt_bundle_with_exemptions(exemptions);

    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&CheckFastaRequest {
            fasta: String::from(HAZARD_SEQ),
            common: RequestCommon {
                region: synthclient::api::Region::All,
                provider_reference: None,
                elt_pem: Some(elt.to_file_contents().unwrap()),
                // The exact value doesn't matter, as the integration tests
                // launch hdbserver with --yubico-api-client-id allow_all
                otp: Some("cccjgjgkhcbbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb".to_owned()),
            },
        })
        .send()
        .unwrap();

    let status = resp.status();
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(status, 200, "bad status code: {answer:?}");
    assert_eq!(
        answer.synthesis_permission, expected_permission,
        "permission should have been {expected_permission:?}: {:?}",
        answer
    );
    assert_eq!(answer.warnings, vec![]);
    assert_all_records_are_matched(&answer, true);
}

#[test]
fn test_elt_missing_otp() {
    initialize();
    let client = reqwest::blocking::Client::new();
    let (elt, _) = create_elt_bundle_with_exemptions(vec![]);

    let resp = client
        .post(format!("{}/v1/screen", ENDPOINT))
        .json::<CheckFastaRequest>(&CheckFastaRequest {
            fasta: String::from(HAZARD_SEQ),
            common: RequestCommon {
                region: synthclient::api::Region::All,
                provider_reference: None,
                elt_pem: Some(elt.to_file_contents().unwrap()),
                otp: None,
            },
        })
        .send()
        .unwrap();

    let status = resp.status();
    let answer = resp.json::<ApiResponse>().unwrap();
    assert_eq!(status, 500, "bad status code: {answer:?}");
    assert_eq!(
        answer.synthesis_permission,
        SynthesisPermission::Denied,
        "permission should have been Denied: {:?}",
        answer
    );
    assert_eq!(answer.warnings, vec![]);
    assert_all_records_are_matched(&answer, true);
}

#[test]
fn test_screen_fasta_irrelevant_elt_denied() {
    test_elt(create_exemptions(), SynthesisPermission::Denied);
}

#[test]
fn test_screen_fasta_an_exemption() {
    test_elt(
        vec![Organism::new(
            "Some organism",
            vec![SequenceIdentifier::Id(
                GenbankId::try_new(HAZARD_AN).unwrap(),
            )],
        )],
        SynthesisPermission::Granted,
    );
}

#[test]
fn test_screen_fasta_name_exemption() {
    test_elt(
        vec![Organism::new(
            HAZARD_NAME,
            vec![SequenceIdentifier::Id(GenbankId::try_new("12345").unwrap())],
        )],
        SynthesisPermission::Granted,
    );
}

#[test]
fn test_screen_fasta_hash_exemption() {
    test_elt(
        vec![Organism::new(
            "Some organism",
            vec![SequenceIdentifier::Dna(
                Sequence::try_new(HAZARD_SEQ).unwrap(),
            )],
        )],
        SynthesisPermission::Granted,
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
    assert_eq!(answer.warnings, vec![]);
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
    assert_eq!(answer.warnings, vec![]);

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
    assert_eq!(answer.warnings, vec![]);

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
