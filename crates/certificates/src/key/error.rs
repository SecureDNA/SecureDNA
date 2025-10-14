// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use crate::error::DecodeError;
use crate::error::EncodeError;

#[derive(Error, Debug)]
pub enum SignatureVerificationError {
    /// Errors related to verifying signatures. Obscure by design, to not leak details about the signature or keys.
    #[error("unable to verify the signature")]
    NotVerifiedError,
    #[error(transparent)]
    KeyParseError(#[from] KeyParseError),
}

#[derive(Error, Debug)]
pub enum KeyWriteError {
    #[error("private key write error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Encrypt(#[from] KeyEncryptionError),
}

impl PartialEq for KeyWriteError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(err1), Self::Io(err2)) => err1.to_string() == err2.to_string(),
            (Self::Encode(l0), Self::Encode(r0)) => l0 == r0,
            (Self::Encrypt(l0), Self::Encrypt(r0)) => l0 == r0,
            _ => false,
        }
    }
}

#[derive(Error, Debug)]
#[error("key could not be parsed")]
pub struct KeyParseError;

#[derive(Error, Debug)]
#[error("signature could not be parsed")]
pub struct SignatureParseError;

#[derive(Error, Debug, PartialEq)]
pub enum KeyLoadError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Decrypt(#[from] KeyDecryptionError),
}

#[derive(Debug, Error, PartialEq)]
pub enum KeyEncryptionError {
    #[error("unable to encrypt key")]
    Encrypt,
    #[error("unable to encode key (Pkcs8): {0}")]
    EncodeAsPkcs8(#[from] KeyIntoPkcs8Error),
    #[error("unable to encode key (Encrypted PKI): {0}")]
    EncodeAsEncryptedPki(String),
    #[error("invalid encryption parameters")]
    InvalidParams,
}

#[derive(Debug, Error, PartialEq)]
pub enum KeyDecryptionError {
    #[error("unable to decrypt key")]
    Decrypt,
    #[error("unable to parse key (Pkcs8): {0}")]
    ParsePkcs8(#[from] KeyFromPkcs8Error),
    #[error("unable to parse key (Encrypted PKI): {0}")]
    ParseEncryptedPki(String),
}

#[derive(Debug, Error, PartialEq)]
pub enum KeyIntoPkcs8Error {
    #[error("unable to encode key as ASN.1")]
    Asn1Encode,
}

#[derive(Debug, Error, PartialEq)]
pub enum KeyFromPkcs8Error {
    #[error("unable to parse as ASN.1: {0}")]
    Asn1Parse(String),
    #[error("unexpected OID")]
    UnexpectedOid,
    #[error("unexpected parameters present")]
    UnexpectedParams,
    #[error("unable to parse key bytes")]
    KeyBytesParse,
    #[error("no public key found")]
    NoPublicKey,
    #[error("public key error: {0}")]
    PublicKey(String),
    /// necessary because conversion from pkcs8::Error is not one-to-one. We shouldn't ever see one of these.
    #[error("unexpected: {0}")]
    Unexpected(String),
}

impl From<pkcs8::Error> for KeyFromPkcs8Error {
    fn from(err: pkcs8::Error) -> Self {
        match err {
            pkcs8::Error::KeyMalformed => KeyFromPkcs8Error::KeyBytesParse,
            pkcs8::Error::Asn1(err) => KeyFromPkcs8Error::Asn1Parse(err.to_string()),
            pkcs8::Error::ParametersMalformed => KeyFromPkcs8Error::UnexpectedParams,
            pkcs8::Error::PublicKey(err) => KeyFromPkcs8Error::PublicKey(err.to_string()),
            _ => KeyFromPkcs8Error::KeyBytesParse,
        }
    }
}
