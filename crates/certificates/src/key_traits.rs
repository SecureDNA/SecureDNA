// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{KeyMismatchError, PublicKey, Signature, SignatureVerificationError, SigningKeyPair};

pub trait HasAssociatedSigningKey {
    fn public_key(&self) -> &PublicKey;
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureVerificationError>;
}

pub trait CanLoadSigningKey: HasAssociatedSigningKey {
    type KeyAvailableType: SigningKeyLoaded;
    fn load_key(self, keypair: SigningKeyPair) -> Result<Self::KeyAvailableType, KeyMismatchError>;
}

pub trait SigningKeyLoaded: HasAssociatedSigningKey {
    type KeyUnavailableType: CanLoadSigningKey;

    fn sign(&self, message: &[u8]) -> Signature;
    fn into_key_unavailable(self) -> Self::KeyUnavailableType;
}
