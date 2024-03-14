// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use doprf::{
    active_security::Commitment,
    prf::{CompletedHashValue, HashPart, Query},
    tagged::TaggedHash,
};

/// Trait for "Ristretto-like" types—types that can be converted to and from
/// [u8; SIZE] and have an assigned magic number.
///
/// NOTE: when implementing this trait, check other implementors and pick an
/// unused magic.
pub trait PackableRistretto: TryFrom<Self::Array> + Into<Self::Array> + Send + Sync {
    type Array: Clone + std::fmt::Debug + PartialEq + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;
    const SIZE: usize = std::mem::size_of::<Self::Array>();
    const MAGIC: [u8; 4];
}

impl PackableRistretto for Query {
    type Array = [u8; 32];
    const MAGIC: [u8; 4] = *b"QURY";
}

impl PackableRistretto for HashPart {
    type Array = [u8; 32];
    const MAGIC: [u8; 4] = *b"HPRT";
}

impl PackableRistretto for CompletedHashValue {
    type Array = [u8; 32];
    const MAGIC: [u8; 4] = *b"CHSH";
}

impl PackableRistretto for Commitment {
    type Array = [u8; 32];
    const MAGIC: [u8; 4] = *b"TCBT";
}

impl PackableRistretto for TaggedHash {
    type Array = [u8; 36];
    const MAGIC: [u8; 4] = *b"THSH";
}
