// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::types::ClientRequestType;
use certificates::{DecodeError, SignatureVerificationError};
use doprf::party::KeyserverId;

#[derive(Debug, thiserror::Error)]
pub enum ScepError<Inner: std::error::Error> {
    #[error("bad protocol")]
    BadProtocol,
    #[error("internal error: {0}")]
    InternalError(anyhow::Error),
    #[error("invalid request or response: {0}")]
    InvalidMessage(anyhow::Error),
    #[error("server is overloaded. try again later")]
    Overloaded,
    #[error("exceeded client daily limit of {limit_bp}bp")]
    RateLimitExceeded { limit_bp: u64 },
    #[error("{0}")]
    Inner(#[from] Inner),
}

#[derive(Debug, thiserror::Error)]
pub enum ServerPrevalidation {
    #[error("client version lower than last recorded for this client")]
    VersionRollback,
    #[error("client version unsupported (too low)")]
    ClientVersionTooLow,
    #[error("client version unsupported (too high)")]
    ClientVersionTooHigh,
    #[error("provided certificate from client is invalid")]
    InvalidCert,
    #[error("nucleotide count is invalid")]
    InvalidNTC,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientPrevalidation {
    #[error("server version lower than last recorded for this server")]
    VersionRollback,
    #[error("provided certificate from server is invalid")]
    InvalidCert,
    #[error("server mutual authentication signature is invalid")]
    InvalidSignature,
    #[error("invalid keyserver id: expected {expected}, found {in_cert} in server cert")]
    InvalidKeyserverId {
        expected: KeyserverId,
        in_cert: KeyserverId,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ServerAuthentication {
    #[error("this client has already authenticated")]
    ClientAlreadyAuthenticated,
    #[error("client mutual authentication signature is invalid")]
    InvalidSignature,
    #[error("provided hash_total_count {hash_total_count} is unreasonable based on nucleotide_total_count {nucleotide_total_count}")]
    HtcUnreasonable {
        hash_total_count: u64,
        nucleotide_total_count: u64,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Keyserve {
    #[error("this client has not finished authenticating")]
    ClientNotAuthenticated,
    #[error("client opened with request type {0:?} but tried to keyserve")]
    WrongRequestType(ClientRequestType),
    #[error("client provided too many hashes: asked for {requested}, provided {provided}")]
    TooManyHashes { requested: u64, provided: u64 },
}

#[derive(Debug, thiserror::Error)]
pub enum Screen {
    #[error("this client has not finished authenticating")]
    ClientNotAuthenticated,
    #[error("client opened with request type {0:?} but tried to screen")]
    WrongRequestType(ClientRequestType),
    #[error("client provided too many hashes: asked for {requested}, provided {provided}")]
    TooManyHashes { requested: u64, provided: u64 },
    #[error("client tried ELT-screen-hashes before sending ELT")]
    ScreenBeforeElt,
    #[error("client tried ELT-screen-hashes before sending ELT-seq-hashes")]
    ScreenBeforeEltHashes,
    #[error("ELT validation error: {0}")]
    EltValidation(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ScreenWithEL {
    #[error("this client has not finished authenticating")]
    ClientNotAuthenticated,
    #[error("client opened with request type {0:?} but tried to screen-with-EL")]
    WrongRequestType(ClientRequestType),
    #[error("client ELT_size too big {actual}, configured server maximum is {maximum}")]
    EltSizeTooBig { actual: u64, maximum: u64 },
    #[error("client tried screen-with-EL in wrong state")]
    WrongEltState,
}

#[derive(Debug, thiserror::Error)]
pub enum ELT {
    #[error("this client has not finished authenticating")]
    ClientNotAuthenticated,
    #[error("client tried to send ELT in wrong state")]
    WrongEltState,
    #[error("client ELT did not match promised size")]
    SizeMismatch,
    #[error("client ELT could not be decoded")]
    DecodeError(#[from] DecodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum EltSeqHashes {
    #[error("this client has not finished authenticating")]
    ClientNotAuthenticated,
    #[error("client tried to send ELT-seq-hashes in wrong state")]
    WrongEltState,
}

macro_rules! impl_signature_error {
    ($t:ty) => {
        impl From<SignatureVerificationError> for ScepError<$t> {
            fn from(e: SignatureVerificationError) -> Self {
                match e {
                    SignatureVerificationError::NotVerifiedError => {
                        Self::Inner(<$t>::InvalidSignature)
                    }
                    SignatureVerificationError::KeyParseError(e) => Self::InternalError(e.into()),
                }
            }
        }
    };
}

impl_signature_error!(ClientPrevalidation);
impl_signature_error!(ServerAuthentication);
