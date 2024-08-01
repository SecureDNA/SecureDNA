// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs;
use std::path::Path;

use certificates::file::{load_keypair_from_file, load_token_bundle_from_file, TokenExtension};
use certificates::key_traits::CanLoadKey;
use certificates::{
    ChainTraversal, ExemptionTokenGroup, KeyPair, PublicKey, TokenBundle, TokenGroup,
};

pub fn parse_token_files_and_validate_path_to_root<T>(
    token_file: &Path,
    key_file: &Path,
    passphrase_file: &Path,
    root_public_key: &PublicKey,
) -> Result<(TokenBundle<T>, KeyPair), String>
where
    T: TokenGroup + TokenExtension,
{
    let token_bundle = load_token_bundle_from_file::<T>(token_file)
        .map_err(|err| format!("Failed to load token bundle from file: {err:?}"))?;

    let passphrase = fs::read_to_string(passphrase_file)
        .map_err(|err| format!("Failed to load passphrase file: {err:?}"))?;
    let keypair = load_keypair_from_file(key_file, passphrase.trim())
        .map_err(|err| format!("Failed to load keypair from file: {err:?}"))?;

    if let Err(err) = token_bundle.validate_path_to_issuers(&[*root_public_key], None) {
        return Err(format!(
            "No path to root public key found for token: {err:?}"
        ));
    }

    Ok((token_bundle, keypair))
}

pub fn check_token_bundle_and_associated_key<T>(
    token_file: &Path,
    key_file: &Path,
    passphrase_file: &Path,
    root_public_key: &PublicKey,
) -> Result<(), String>
where
    T: TokenGroup + TokenExtension,
    T::Token: CanLoadKey,
{
    let (token_bundle, keypair) = parse_token_files_and_validate_path_to_root::<T>(
        token_file,
        key_file,
        passphrase_file,
        root_public_key,
    )?;

    token_bundle
        .token
        .load_key(keypair)
        .map_err(|err| format!("Failed to match keypair with token: {err:?}"))?;
    Ok(())
}

pub fn check_exemption_bundle_and_associated_key(
    token_file: &Path,
    key_file: &Path,
    passphrase_file: &Path,
    root_public_key: &PublicKey,
) -> Result<(), String> {
    let (token_bundle, keypair) = parse_token_files_and_validate_path_to_root::<ExemptionTokenGroup>(
        token_file,
        key_file,
        passphrase_file,
        root_public_key,
    )?;

    token_bundle
        .token
        .load_key(keypair)
        .map_err(|err| format!("Failed to match keypair with token: {err:?}"))?;
    Ok(())
}
