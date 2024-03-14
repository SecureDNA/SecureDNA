// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Status of a `Certificate` or `CertificateRequest`'s private key.
//!
//! The key status restricts functionality based on the availability of the private key.

use std::fmt::Debug;

use thiserror::Error;

use crate::keypair::{KeyPair, PublicKey};

/// Key state for unavailable private key.
/// This is the default state for Certificates on being deserialised.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyUnavailable;
impl KeyUnavailable {
    pub fn load_key(
        keypair: KeyPair,
        public_key: &PublicKey,
    ) -> Result<KeyAvailable, KeyMismatchError> {
        if &keypair.public_key() != public_key {
            return Err(KeyMismatchError);
        }
        Ok(KeyAvailable(keypair))
    }
}

/// Key state required in order for a certificate to be able to sign another certificate.
pub struct KeyAvailable(KeyPair);
impl KeyAvailable {
    pub fn kp(&self) -> &KeyPair {
        &self.0
    }
}

impl Debug for KeyAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyAvailable")
    }
}

#[derive(Error, Debug, PartialEq)]
#[error("attempted to load private key which does not correspond to the certificate")]
pub struct KeyMismatchError;
