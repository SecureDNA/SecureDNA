// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::{Path, PathBuf};

use crate::shims::error::CertCliError;
use certificates::file::TokenExtension;
use certificates::file::CERT_EXT;
use certificates::file::CERT_REQUEST_EXT;
use certificates::file::KEY_PRIV_EXT;
use certificates::now_utc;
use certificates::CertificateBundle;
use certificates::CertificateRequest;
use certificates::PublicKey;
use certificates::Request;
use certificates::Role;
use certificates::TokenGroup;

const DEFAULT_FOLDER: &str = "SecureDNA";

pub fn cli_default_directory() -> Result<PathBuf, CertCliError> {
    let mut path = dirs::home_dir().ok_or(CertCliError::DefaultDirectoryPath)?;
    path.push(DEFAULT_FOLDER);
    Ok(path)
}

pub fn set_appropriate_filepath_and_create_default_dir_if_required<F>(
    output: Option<&PathBuf>,
    extension: &str,
    default_filename_fn: F,
    default_dir: &Path,
) -> Result<PathBuf, CertCliError>
where
    F: Fn() -> PathBuf,
{
    let output = match output {
        Some(path) if path.extension().is_none() => path.with_extension(extension),
        Some(path) => path.to_owned(),
        None => default_filename_fn(),
    };

    // We only create the default directory, not other custom directories
    if output.parent() == Some(default_dir) {
        std::fs::create_dir_all(default_dir)
            .map_err(|_| CertCliError::DefaultDirectoryCreation(default_dir.to_owned()))?;
    }
    Ok(output.to_owned())
}

pub(crate) fn get_default_filename_for_key(public_key: &PublicKey) -> PathBuf {
    let filename: String = public_key.to_string().chars().take(16).collect();
    PathBuf::from(filename).with_extension(KEY_PRIV_EXT)
}

pub(crate) fn get_default_filename_for_cert_bundle<R: Role>(cb: &CertificateBundle<R>) -> PathBuf {
    let filename = match cb.get_lead_cert() {
        Ok(cert) => format!(
            "{}-{}-{}",
            cert.request_id(),
            cert.hierarchy_level().short_name(),
            now_utc().date(),
        ),
        Err(_) => now_utc().date().to_string(),
    };

    PathBuf::from(filename).with_extension(CERT_EXT)
}

pub(crate) fn get_default_filename_for_cert_request<R: Role, K>(
    req: &CertificateRequest<R, K>,
) -> PathBuf {
    let filename = format!(
        "{}-{}-{}",
        req.request_id(),
        req.hierarchy_level().short_name(),
        now_utc().date(),
    );
    PathBuf::from(filename).with_extension(CERT_REQUEST_EXT)
}

pub(crate) fn get_default_filename_for_token_request<T: TokenGroup + TokenExtension>(
    tr: &T::TokenRequest,
) -> PathBuf {
    let filename = format!("{}-{}", tr.request_id(), now_utc().date());
    PathBuf::from(filename).with_extension(T::REQUEST_EXT)
}
