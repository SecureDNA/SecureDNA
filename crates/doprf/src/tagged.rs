// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::prf::CompressedCompletedHashValue;

/// A 4-byte header prepended to each Ristretto hash in a tagged hash stream. It
/// describes whether the hash starts a new record, its index in the record, and
/// the "hash type", which is an index into a list of hash types negotiated
/// out-of-band.
///
/// ```text
///  ┌> reserved (3b)
///  │ ┌> starts_new_record (1b)
///  │ │
///  │ │  ┌> hash_type_index (4b)
/// ┌┴┐│┌─┴┐ ┌──index_in_record (24b)─┐
/// 76543210 76543210 76543210 76543210
/// 0        1        2        3
/// ```

#[derive(
    Default,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    Unaligned,
)]
#[repr(C)]
pub struct HashTag([u8; 4]);

impl HashTag {
    /// Create a new hash header from the given values.
    ///
    /// * The `hash_type_index` value should be in the range 0..=15. Otherwise,
    ///   is truncated to 4 bits (`n & 0xf`).
    /// * The `index_in_record` value should be in the range 0..=0xffffff.
    ///   Otherwise, it is truncated to 24 bits (`n & 0xffffff`).
    ///
    pub fn new(starts_new_record: bool, hash_type_index: u8, index_in_record: usize) -> Self {
        Self(u32::to_be_bytes(
            ((starts_new_record as u32) << 28)
                | (((hash_type_index & 0xf) as u32) << 24)
                | (index_in_record & 0xffffff) as u32,
        ))
    }

    /// Create a hash header for a "dummy" TaggedHash. This is created when the
    /// input is too short to create any windows. We send a fictitious hash with
    /// the `starts_new_record` bit set so that the HDB can reconstruct correct
    /// record indices.
    pub fn dummy() -> Self {
        Self::new(true, 0, 0)
    }

    /// Does this hash mark the start of a new record?
    pub fn starts_new_record(&self) -> bool {
        self.0[0] & 0x10 != 0
    }

    /// Return a number between 0 and 15 indexing into the HTDV (hash type
    /// description vector; a list of requested hash types for the order.)
    pub fn hash_type_index(&self) -> u8 {
        self.0[0] & 0x0f
    }

    /// Return the index into the DNA order, counting from 0 in base pairs, of
    /// the window that originated this hash.
    pub fn index_in_record(&self) -> usize {
        (u32::from_be_bytes(self.0) & 0xffffff) as usize
    }

    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for HashTag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("HashTag")
            .field("starts_new_record", &self.starts_new_record())
            .field("hash_type_index", &self.hash_type_index())
            .field("index_in_record", &self.index_in_record())
            .finish()
    }
}

/// A completed Ristretto hash tagged with a 4-byte header.
#[derive(Debug, Clone, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub struct TaggedHash {
    pub tag: HashTag,
    pub hash: CompressedCompletedHashValue,
}

impl TaggedHash {
    pub const SIZE: usize = 36;
}

impl From<[u8; 36]> for TaggedHash {
    fn from(value: [u8; 36]) -> Self {
        let (tag, etc) = value.split_first_chunk().unwrap();
        let hash = etc.try_into().unwrap();
        Self {
            tag: HashTag(*tag),
            hash: CompressedCompletedHashValue::from(&hash),
        }
    }
}

impl From<TaggedHash> for [u8; 36] {
    fn from(value: TaggedHash) -> Self {
        let mut buf = [0; 36];
        buf[..4].copy_from_slice(value.tag.0.as_slice());
        buf[4..].copy_from_slice(value.hash.as_bytes());
        buf
    }
}

impl From<TaggedHash> for CompressedCompletedHashValue {
    fn from(value: TaggedHash) -> Self {
        value.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    quickcheck! {
        fn qc_hashtag_roundtrips(starts_new_record: bool, h: u8, i: usize) -> bool {
            let hash_type_index = h & 0xf;
            let index_in_record = i & 0xffffff;
            let hash_tag = HashTag::new(starts_new_record, hash_type_index, index_in_record);
            hash_tag.starts_new_record() == starts_new_record
                && hash_tag.hash_type_index() == hash_type_index
                && hash_tag.index_in_record() == index_in_record
        }
    }
}
