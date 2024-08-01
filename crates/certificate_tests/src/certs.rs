// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs;
use std::path::Path;

use certificates::file::{
    load_certificate_bundle_from_file, load_keypair_from_file, load_public_key_from_file,
};
use certificates::{CertificateBundle, ChainTraversal, PublicKey, Role};

/// Validates .cert, .pub, .priv, and .passphrase files.
/// Checks that the public keys match.
/// Checks that there is a valid path to the root public key.
/// Checks that the private key can be decrypted with the passphrase and matches the public key.
#[macro_export]
macro_rules! validate_public_and_private_cert_files {
    ($certs_dir:expr, $root_public_key:expr, $role:ident; $($cert_type:expr),+) => {
        $(
            paste::item! {
                #[test]
                fn [<check_ $certs_dir:lower _ $role:lower _ $cert_type:snake _cert>]() {
                    let base_path = ::std::path::PathBuf::from($certs_dir)
                        .join(format!("{}-{}", stringify!($role).to_lowercase(), $cert_type));
                    let cert_file = base_path.with_extension("cert");
                    let pub_file = base_path.with_extension("pub");
                    let priv_file = base_path.with_extension("priv");
                    let passphrase_file = base_path.with_extension("passphrase");

                    let result = $crate::certs::validate_all_cert_files::<$role>(
                        &cert_file,
                        &pub_file,
                        &priv_file,
                        &passphrase_file,
                        &$root_public_key,
                    );
                    assert!(
                        result.is_ok(),
                        "{} {} {} cert checks failed: {:?}",
                        stringify!($certs_dir),
                        stringify!($role),
                        $cert_type,
                        result.err()
                    );
                }
            }
        )+
    };
}

/// Validates .cert and .pub files.
/// Checks that the public keys match.
/// Checks that there is a valid path to the root public key.
#[macro_export]
macro_rules! validate_public_cert_files {
    ($certs_dir:expr, $root_public_key:expr, $role:ident; $($cert_type:expr),+) => {
        $(
            paste::item! {
                #[test]
                fn [<check_ $certs_dir:lower _ $role:lower _ $cert_type:snake _cert>]() {
                    let base_path = PathBuf::from($certs_dir)
                        .join(format!("{}-{}", stringify!($role).to_lowercase(), $cert_type));
                    let cert_file = base_path.with_extension("cert");
                    let pub_file = base_path.with_extension("pub");

                    let result = $crate::certs::validate_cert_public_files::<$role>(
                        &cert_file,
                        &pub_file,
                        &$root_public_key,
                    );
                    assert!(
                        result.is_ok(),
                        "{} {} {} cert checks failed: {:?}",
                        stringify!($certs_dir),
                        stringify!($role),
                        $cert_type,
                        result.err()
                    );
                }
            }
        )+
    };
}

/// Validates .cert and .pub files.
/// Checks that the public keys match.
/// Checks that there is a valid path to the root public key.
pub fn validate_cert_public_files<R: Role>(
    cert_file: &Path,
    pub_file: &Path,
    root_public_key: &PublicKey,
) -> Result<CertificateBundle<R>, String> {
    let cert_bundle = load_certificate_bundle_from_file::<R>(cert_file)
        .map_err(|err| format!("Failed to load cert bundle from file: {err:?}"))?;

    let pub_key = load_public_key_from_file(pub_file).map_err(|err| {
        format!("Failed to load public key from file: {pub_file:?}, error: {err:?}")
    })?;

    cert_bundle
        .validate_path_to_issuers(&[*root_public_key], None)
        .map_err(|err| format!("No path to root public key found for certificate: {err:?}"))?;

    if *cert_bundle.get_lead_cert().unwrap().public_key() != pub_key {
        return Err(format!(
            "Cert public key does not match key found in .pub file for {cert_file:?}",
        ));
    }
    Ok(cert_bundle)
}

/// Validates .cert, .pub, .priv, and .passphrase files.
/// Checks that the public keys match.
/// Checks that there is a valid path to the root public key.
/// Checks that the private key can be decrypted with the passphrase and matches the public key.
pub fn validate_all_cert_files<R: Role>(
    cert_file: &Path,
    pub_file: &Path,
    priv_file: &Path,
    passphrase_file: &Path,
    root_public_key: &PublicKey,
) -> Result<(), String> {
    let cert_bundle = validate_cert_public_files::<R>(cert_file, pub_file, root_public_key)?;

    let passphrase = fs::read_to_string(passphrase_file)
        .map_err(|err| format!("Failed to load passphrase file: {err:?}"))?;
    let keypair = load_keypair_from_file(priv_file, passphrase.trim())
        .map_err(|err| format!("Failed to load keypair from file: {err:?}"))?;

    cert_bundle
        .get_lead_cert()
        .unwrap()
        .clone()
        .load_key(keypair)
        .map_err(|err| format!("Failed to match keypair with cert: {err:?}"))?;
    Ok(())
}
