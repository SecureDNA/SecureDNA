// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use certificates::{
    file::FileError, ExpirationError, FormatError, IssuanceError, KeyLoadError, KeyMismatchError,
    KeyWriteError,
};

use crate::passphrase_reader::PassphraseReaderError;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CertCliError {
    #[error("The public key provided for use in auditing could not be parsed.")]
    AuditKeyParseError,
    #[error("Unsuccessfully attempted to create a default directory at {:?} for your certificate files.", .0)]
    DefaultDirectoryCreation(PathBuf),
    #[error("Unsuccessfully attempted to determine a default directory for your certificate files. Please supply destinations for the files you are creating.")]
    DefaultDirectoryPath,
    #[error("Unable to issue: {0}.")]
    IssuanceError(#[from] IssuanceError),
    #[error("Please enter at least one issuer's public key in order to inspect possible paths to that issuer.")]
    IssuerPublicKeyRequired,
    #[error("Public key supplied could not be parsed.")]
    PublicKeyError,
    #[error("Unable to save the private key.")]
    KeyWriteError,
    #[error("Could not use private key provided. Unexpected file contents")]
    KeyDecode,
    #[error("Could not use private key provided. Perhaps you entered the wrong passphrase")]
    KeyDecrypt,
    #[error("Could not use private key provided. Perhaps the private key does not correspond to the certificate")]
    KeyMismatch,
    #[error("Unable to display the certificate in the format requested.")]
    FormatError,
    #[error("Unable to create a certificate with the supplied expiry information: {0}.")]
    Expiration(#[from] ExpirationError),
    #[error("Cannot merge certificate files {0} and {1} because they are not derived from the same certificate request.")]
    CouldNotMerge(PathBuf, PathBuf),
    #[error("No valid certificate(s) found in the file provided. This may mean that the certificate has expired.")]
    NoSuitableCertificate,
    #[error("Where a public key is supplied for audit purposes, the audit recipient's email address must also be provided.")]
    MissingAuditEmail,
    #[error("Where an email address is supplied for audit purposes, the audit recipient's public key must also be provided.")]
    MissingAuditPublicKey,
    #[error(transparent)]
    CouldNotReadPassphrase(#[from] PassphraseReaderError),
    #[error("Please supply no more than one option from --create-new-key, --key-from-hex, --key-from-file.")]
    TooManyKeyArgs,
    #[error(transparent)]
    FileError(FileError),
    #[error("The use of the --notify option is only valid for exemption leaf certificates.")]
    EmailsToNotifyNotAllowed,
    #[error("The use of the --allow-blinding option is only valid for exemption certificates.")]
    AllowBlindingNotAllowed,
}

impl From<FileError> for CertCliError {
    fn from(value: FileError) -> Self {
        match value {
            FileError::KeyLoadError(error) => error.into(),
            _ => Self::FileError(value),
        }
    }
}

impl From<KeyLoadError> for CertCliError {
    fn from(value: KeyLoadError) -> Self {
        match value {
            KeyLoadError::Decode(_) => Self::KeyDecode,
            KeyLoadError::Decrypt(_) => Self::KeyDecrypt,
        }
    }
}

impl From<KeyMismatchError> for CertCliError {
    fn from(_: KeyMismatchError) -> Self {
        Self::KeyMismatch
    }
}

impl From<KeyWriteError> for CertCliError {
    fn from(_: KeyWriteError) -> Self {
        Self::KeyWriteError
    }
}

impl From<FormatError> for CertCliError {
    fn from(_: FormatError) -> Self {
        Self::FormatError
    }
}
