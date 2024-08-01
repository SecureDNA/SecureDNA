// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::types::ClientRequestType;
use certificates::{Exemption, Manufacturer, SignatureVerificationError, TokenBundleError};
use doprf::party::KeyserverId;
use shared_types::error::{InvalidClientTokenBundle, InvalidInfrastructureTokenBundle};

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
    #[error(transparent)]
    InvalidCert(InvalidClientTokenBundle<Manufacturer>),
    #[error("nucleotide count is invalid")]
    InvalidNTC,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientPrevalidation {
    #[error("server version lower than last recorded for this server")]
    VersionRollback,
    #[error(transparent)]
    InvalidCert(InvalidInfrastructureTokenBundle),
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
    #[error(transparent)]
    RevokedCert(InvalidClientTokenBundle<Manufacturer>),
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
    #[error("client tried exemption-screen-hashes before sending exemption")]
    ScreenBeforeEt,
    #[error("client tried exemption-screen-hashes before sending exemption-seq-hashes")]
    ScreenBeforeEtHashes,
    #[error("exemption token validation error: {0}")]
    EtValidation(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ScreenWithEL {
    #[error("this client has not finished authenticating")]
    ClientNotAuthenticated,
    #[error("client opened with request type {0:?} but tried to screen-with-exemption")]
    WrongRequestType(ClientRequestType),
    #[error("client ELT_size too big {actual}, configured server maximum is {maximum}")]
    EtSizeTooBig { actual: u64, maximum: u64 },
    #[error("client tried screen-with-exemption in wrong state")]
    WrongEtState,
}

#[derive(Debug, thiserror::Error)]
pub enum ET {
    #[error("this client has not finished authenticating")]
    ClientNotAuthenticated,
    #[error("client tried to send exemption token in wrong state")]
    WrongEtState,
    #[error("client exemption token did not match promised size")]
    SizeMismatch,
    #[error("client exemption token JSON could not be decoded")]
    JsonDecodeError(#[from] serde_json::Error),
    #[error("client exemption token PEM could not be decoded")]
    PemDecodeError(#[from] TokenBundleError<Exemption>),
}

#[derive(Debug, thiserror::Error)]
pub enum EtSeqHashes {
    #[error("this client has not finished authenticating")]
    ClientNotAuthenticated,
    #[error("client tried to send exemption-seq-hashes in wrong state")]
    WrongEtState,
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
