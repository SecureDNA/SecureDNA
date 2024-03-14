// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use pem::PemError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum EncodeError {
    #[error("could not ASN encode: {0}")]
    AsnEncode(String),
    #[error("unexpected tag, expected {0}, got {1}")]
    UnexpectedTag(String, String),
}

#[derive(Error, Debug, PartialEq)]
pub enum DecodeError {
    #[error(transparent)]
    PemError(#[from] PemError),
    #[error("could not ASN decode: {0}")]
    AsnDecode(String),
    #[error("unexpected tag, expected {0}, got {1}")]
    UnexpectedPEMTag(String, String),
    #[error("unable to parse decoded bytes into required type")]
    ParseError,
}
