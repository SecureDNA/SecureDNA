// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use certificate_tests::token::{
    check_exemption_bundle_and_associated_key, check_token_bundle_and_associated_key,
};
use certificates::{DatabaseTokenGroup, KeyserverTokenGroup, SynthesizerTokenGroup};

#[path = "test_common.rs"]
mod test_common;

use test_common::{
    TEST_DIR, TEST_EXEMPTION_ROOT, TEST_INFRASTRUCTURE_ROOT, TEST_MANUFACTURER_ROOT,
};

#[test]
fn check_test_keyserver_token_bundle_1_to_5() {
    for index in 1..=5 {
        let base_path = PathBuf::from(TEST_DIR).join(format!("keyserver-token-{:02}", index));
        let token_file: PathBuf = base_path.with_extension("kt");
        let key_file: PathBuf = base_path.with_extension("priv");
        let passphrase_file: PathBuf = base_path.with_extension("passphrase");

        let result = check_token_bundle_and_associated_key::<KeyserverTokenGroup>(
            &token_file,
            &key_file,
            &passphrase_file,
            &TEST_INFRASTRUCTURE_ROOT,
        );
        assert!(
            result.is_ok(),
            "Test keyserver token {index} checks failed: {:?}",
            result.err()
        );
    }
}

#[test]
fn check_test_database_token_bundle() {
    let base_path = PathBuf::from(TEST_DIR).join("database-token");
    let token_file: PathBuf = base_path.with_extension("dt");
    let key_file: PathBuf = base_path.with_extension("priv");
    let passphrase_file: PathBuf = base_path.with_extension("passphrase");

    let result = check_token_bundle_and_associated_key::<DatabaseTokenGroup>(
        &token_file,
        &key_file,
        &passphrase_file,
        &TEST_INFRASTRUCTURE_ROOT,
    );
    assert!(
        result.is_ok(),
        "Test database token checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_test_synthesizer_token_bundle() {
    let base_path = PathBuf::from(TEST_DIR).join("synthesizer-token");
    let token_file: PathBuf = base_path.with_extension("st");
    let key_file: PathBuf = base_path.with_extension("priv");
    let passphrase_file: PathBuf = base_path.with_extension("passphrase");

    let result = check_token_bundle_and_associated_key::<SynthesizerTokenGroup>(
        &token_file,
        &key_file,
        &passphrase_file,
        &TEST_MANUFACTURER_ROOT,
    );
    assert!(
        result.is_ok(),
        "Test synthesizer token checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_test_exemption_token_bundle() {
    let base_path = PathBuf::from(TEST_DIR).join("exemption-token");
    let token_file: PathBuf = base_path.with_extension("et");
    let key_file: PathBuf = base_path.with_extension("priv");
    let passphrase_file: PathBuf = base_path.with_extension("passphrase");

    let result = check_exemption_bundle_and_associated_key(
        &token_file,
        &key_file,
        &passphrase_file,
        &TEST_EXEMPTION_ROOT,
    );
    assert!(
        result.is_ok(),
        "Test exemption token checks failed: {:?}",
        result.err()
    );
}
