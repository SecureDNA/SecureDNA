// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use anyhow::Context;

use certificates::{
    file::{load_keypair_from_file, load_token_bundle_from_file, TokenExtension},
    Certificate, KeyPair, KeyUnavailable, PemDecodable, Role, TokenBundle, TokenGroup,
};

pub fn read_tokenbundle<T: TokenGroup + TokenExtension>(
    path: impl AsRef<Path>,
) -> anyhow::Result<TokenBundle<T>> {
    load_token_bundle_from_file(path.as_ref()).context("reading server token bundle")
}

pub fn read_keypair(path: impl AsRef<Path>, passphrase: &str) -> anyhow::Result<KeyPair> {
    load_keypair_from_file(path.as_ref(), passphrase.as_bytes()).context("reading server keypair")
}

pub fn read_certificates<R: Role>(
    cert_directory: impl AsRef<Path>,
) -> anyhow::Result<Vec<Certificate<R, KeyUnavailable>>> {
    let cert_directory = cert_directory.as_ref();
    let mut certificates = Vec::new();
    for entry in std::fs::read_dir(cert_directory)
        .with_context(|| format!("reading cert directory {cert_directory:?}"))?
    {
        let entry =
            entry.with_context(|| format!("reading entry in cert directory {cert_directory:?}"))?;
        let path = entry.path();
        // TODO: certificate_client doesn't seem to have a way to load a plain cert (instead of a bundle)
        let bytes = std::fs::read(&path).with_context(|| format!("reading {path:?}"))?;
        let certificate = Certificate::<R, KeyUnavailable>::from_pem(&bytes)
            .with_context(|| format!("parsing PEM from {path:?}"))?;
        certificates.push(certificate);
    }

    Ok(certificates)
}
