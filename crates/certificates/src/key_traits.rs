// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{KeyMismatchError, KeyPair, PublicKey, Signature, SignatureVerificationError};

pub trait HasAssociatedKey {
    fn public_key(&self) -> &PublicKey;
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureVerificationError>;
}

pub trait CanLoadKey: HasAssociatedKey {
    type KeyAvailableType: KeyLoaded;
    fn load_key(self, keypair: KeyPair) -> Result<Self::KeyAvailableType, KeyMismatchError>;
}

pub trait KeyLoaded: HasAssociatedKey {
    type KeyUnavailableType: CanLoadKey;

    fn sign(&self, message: &[u8]) -> Signature;
    fn into_key_unavailable(self) -> Self::KeyUnavailableType;
}
