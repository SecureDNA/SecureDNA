// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use certificates::file::{
    load_certificate_bundle_from_file, load_keypair_from_file, load_token_bundle_from_file,
    TokenExtension,
};
use certificates::{
    CanLoadKey, CertificateBundle, ChainTraversal, DatabaseTokenGroup, Infrastructure,
    KeyserverTokenGroup, Manufacturer, PublicKey, Role, SynthesizerTokenGroup, TokenGroup,
};
use std::fs;
use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;

static CERTS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/certs");

static INFRASTRUCTURE_ROOT_CERT_BUNDLE: Lazy<CertificateBundle<Infrastructure>> = Lazy::new(|| {
    let root_cert_file: PathBuf =
        format!("{CERTS_DIR}/infrastructure_roots/infrastructure-root.cert").into();
    load_certificate_bundle_from_file::<Infrastructure>(&root_cert_file)
        .expect("could not load infrastructure root cert")
});

static INFRASTRUCTURE_ROOT_PUBLIC_KEY: Lazy<PublicKey> = Lazy::new(|| {
    *INFRASTRUCTURE_ROOT_CERT_BUNDLE
        .get_lead_cert()
        .unwrap()
        .public_key()
});

static MANUFACTURER_ROOT_CERT_BUNDLE: Lazy<CertificateBundle<Manufacturer>> = Lazy::new(|| {
    let root_cert_file: PathBuf =
        format!("{CERTS_DIR}/manufacturer_roots/manufacturer-root.cert").into();
    load_certificate_bundle_from_file::<Manufacturer>(&root_cert_file)
        .expect("could not load manufacturer root cert")
});

static MANUFACTURER_ROOT_PUBLIC_KEY: Lazy<PublicKey> = Lazy::new(|| {
    *MANUFACTURER_ROOT_CERT_BUNDLE
        .get_lead_cert()
        .unwrap()
        .public_key()
});

static CERT_KEY_PASSPHRASE: &str = "test";

#[test]
fn check_test_keyserver_token_bundle_1_to_5() {
    for index in 1..=5 {
        let token_file: PathBuf = format!("{CERTS_DIR}/keyserver-token-{index}.kt").into();
        let key_file: PathBuf = format!("{CERTS_DIR}/keyserver-token-{index}.priv").into();
        let passphrase_file: PathBuf = format!("{CERTS_DIR}/keyserver-passphrase.txt").into();

        let result = check_token_bundle_and_associated_key::<KeyserverTokenGroup>(
            &token_file,
            &key_file,
            &passphrase_file,
            &INFRASTRUCTURE_ROOT_PUBLIC_KEY,
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
    let token_file: PathBuf = format!("{CERTS_DIR}/database-token.dt").into();
    let key_file: PathBuf = format!("{CERTS_DIR}/database-token.priv").into();
    let passphrase_file: PathBuf = format!("{CERTS_DIR}/database-passphrase.txt").into();

    let result = check_token_bundle_and_associated_key::<DatabaseTokenGroup>(
        &token_file,
        &key_file,
        &passphrase_file,
        &INFRASTRUCTURE_ROOT_PUBLIC_KEY,
    );
    assert!(
        result.is_ok(),
        "Test database token checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_test_synthesizer_token_bundle() {
    let token_file: PathBuf = format!("{CERTS_DIR}/synthesizer-token.st").into();
    let key_file: PathBuf = format!("{CERTS_DIR}/synthesizer-token.priv").into();
    let passphrase_file: PathBuf = format!("{CERTS_DIR}/synthesizer-passphrase.txt").into();

    let result = check_token_bundle_and_associated_key::<SynthesizerTokenGroup>(
        &token_file,
        &key_file,
        &passphrase_file,
        &MANUFACTURER_ROOT_PUBLIC_KEY,
    );
    assert!(
        result.is_ok(),
        "Test synthesizer token checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_infrastructure_root_cert() {
    let cert_file: PathBuf = format!("{CERTS_DIR}/infrastructure-root.cert").into();
    let key_file: PathBuf = format!("{CERTS_DIR}/infrastructure-root.priv").into();

    let result = check_cert_bundle_and_associated_key::<Infrastructure>(
        &cert_file,
        &key_file,
        &INFRASTRUCTURE_ROOT_PUBLIC_KEY,
    );
    assert!(
        result.is_ok(),
        "Test infrastructure root cert checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_infrastructure_intermediate_cert() {
    let cert_file: PathBuf = format!("{CERTS_DIR}/infrastructure-intermediate.cert").into();
    let key_file: PathBuf = format!("{CERTS_DIR}/infrastructure-intermediate.priv").into();

    let result = check_cert_bundle_and_associated_key::<Infrastructure>(
        &cert_file,
        &key_file,
        &INFRASTRUCTURE_ROOT_PUBLIC_KEY,
    );
    assert!(
        result.is_ok(),
        "Test infrastructure intermediate cert checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_infrastructure_leaf_cert() {
    let cert_file: PathBuf = format!("{CERTS_DIR}/infrastructure-leaf.cert").into();
    let key_file: PathBuf = format!("{CERTS_DIR}/infrastructure-leaf.priv").into();

    let result = check_cert_bundle_and_associated_key::<Infrastructure>(
        &cert_file,
        &key_file,
        &INFRASTRUCTURE_ROOT_PUBLIC_KEY,
    );
    assert!(
        result.is_ok(),
        "Test infrastructure leaf cert checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_manufacturer_root_cert() {
    let cert_file: PathBuf = format!("{CERTS_DIR}/manufacturer-root.cert").into();
    let key_file: PathBuf = format!("{CERTS_DIR}/manufacturer-root.priv").into();

    let result = check_cert_bundle_and_associated_key::<Manufacturer>(
        &cert_file,
        &key_file,
        &MANUFACTURER_ROOT_PUBLIC_KEY,
    );
    assert!(
        result.is_ok(),
        "Test manufacturer root cert checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_manufacturer_intermediate_cert() {
    let cert_file: PathBuf = format!("{CERTS_DIR}/manufacturer-intermediate.cert").into();
    let key_file: PathBuf = format!("{CERTS_DIR}/manufacturer-intermediate.priv").into();

    let result = check_cert_bundle_and_associated_key::<Manufacturer>(
        &cert_file,
        &key_file,
        &MANUFACTURER_ROOT_PUBLIC_KEY,
    );
    assert!(
        result.is_ok(),
        "Test manufacturer intermediate cert checks failed: {:?}",
        result.err()
    );
}

#[test]
fn check_manufacturer_leaf_cert() {
    let cert_file: PathBuf = format!("{CERTS_DIR}/manufacturer-leaf.cert").into();
    let key_file: PathBuf = format!("{CERTS_DIR}/manufacturer-leaf.priv").into();

    let result = check_cert_bundle_and_associated_key::<Manufacturer>(
        &cert_file,
        &key_file,
        &MANUFACTURER_ROOT_PUBLIC_KEY,
    );
    assert!(
        result.is_ok(),
        "Test manufacturer leaf cert checks failed: {:?}",
        result.err()
    );
}

fn check_token_bundle_and_associated_key<T>(
    token_file: &Path,
    key_file: &Path,
    passphrase_file: &Path,
    root_public_key: &PublicKey,
) -> Result<(), String>
where
    T: TokenGroup + TokenExtension,
    T::Token: CanLoadKey,
{
    let token_bundle = load_token_bundle_from_file::<T>(token_file)
        .map_err(|err| format!("Failed to load token bundle from file: {err:?}"))?;

    let passphrase = fs::read_to_string(passphrase_file)
        .map_err(|err| format!("Failed to load passphrase file: {err:?}"))?;
    let keypair = load_keypair_from_file(key_file, passphrase.trim())
        .map_err(|err| format!("Failed to load keypair from file: {err:?}"))?;

    if let Err(err) = token_bundle.validate_path_to_issuers(&[*root_public_key]) {
        return Err(format!(
            "No path to root public key found for token: {err:?}"
        ));
    }

    token_bundle
        .token
        .load_key(keypair)
        .map_err(|err| format!("Failed to match keypair with token: {err:?}"))?;
    Ok(())
}

fn check_cert_bundle_and_associated_key<R: Role>(
    cert_file: &Path,
    key_file: &Path,
    root_public_key: &PublicKey,
) -> Result<(), String> {
    let cert_bundle = load_certificate_bundle_from_file::<R>(cert_file)
        .map_err(|err| format!("Failed to load cert bundle from file: {err:?}"))?;

    let keypair = load_keypair_from_file(key_file, CERT_KEY_PASSPHRASE).map_err(|err| {
        format!("Failed to load keypair with passphrase '{CERT_KEY_PASSPHRASE}': {err:?}")
    })?;

    if let Err(err) = cert_bundle.validate_path_to_issuers(&[*root_public_key]) {
        return Err(format!(
            "No path to root public key found for certificate: {err:?}"
        ));
    }

    cert_bundle
        .get_lead_cert()
        .unwrap()
        .clone()
        .load_key(keypair)
        .map_err(|err| format!("Failed to match keypair with cert: {err:?}"))?;
    Ok(())
}
