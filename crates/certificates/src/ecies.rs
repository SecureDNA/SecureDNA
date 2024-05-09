// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fmt,
    fmt::{Debug, Display},
    str::FromStr,
};

use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

use crate::asn_encode_as_octet_string_impl;

/// A public key for use with the Elliptic Curve Integrated Encryption Scheme (ECIES).
/// This key enables the encryption of messages intended exclusively for a recipient holding the corresponding private key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr)]
pub struct EncryptionPublicKey([u8; Self::LEN]);

impl EncryptionPublicKey {
    const LEN: usize = 33;
}

asn_encode_as_octet_string_impl!(EncryptionPublicKey, EncryptionPublicKey::LEN);

impl Display for EncryptionPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for EncryptionPublicKey {
    type Err = EncryptionKeyParseError;

    /// Expects a hex encoded secp256k1 public key
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = hex::decode(s)
            .map_err(|_| EncryptionKeyParseError)?
            .try_into()
            .map_err(|_| EncryptionKeyParseError)?;
        Ok(Self(x))
    }
}

impl Debug for EncryptionPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EncryptionPublicKey")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Error, Debug)]
#[error("encryption key could not be parsed")]
pub struct EncryptionKeyParseError;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::EncryptionPublicKey;

    #[test]
    fn can_parse_ecies_public_key() {
        let (_, pk) = ecies::utils::generate_keypair();
        let hex = hex::encode(pk.serialize_compressed());
        EncryptionPublicKey::from_str(&hex).unwrap();
    }
}
