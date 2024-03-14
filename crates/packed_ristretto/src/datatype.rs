// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::marker::PhantomData;

use doprf::prf::{Query, QueryStateSet};

use crate::{error::DeserializeError, packable::PackableRistretto};

/// Mime / media type that implementations passing `PackedRistrettos` over HTTP should use
pub const HTTP_MIME_TYPE: &str = "application/x-packed-ristrettos; version=1.0";

/// Current version number for the PackedRistrettos format
pub const VERSION: u8 = 1;

/// A packed set of Ristretto-like (implementing [`PackableRistretto`]()) items.
/// The layout is:
///
/// * A 1-byte version (currently 0)
/// * A 4-byte magic number (e.g., b"QURY" or b"HPRT")
/// * A 4-byte length field, equal to the number of *items* (not bytes for those items)
/// * A variable number of bytes, of size `length * 32`
/// * A 4-byte CRC32 of all the previous bytes
///
/// An empty `PackedRistrettos` is valid, and is 13 bytes long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedRistrettos<T: PackableRistretto> {
    items: Vec<T::Array>,
    _p: PhantomData<fn() -> T>,
}

impl<T: PackableRistretto> PackedRistrettos<T> {
    /// Construct a new `PackedRistrettos` from a vec of encoded elements.
    /// Be careful that the elements were encoded from the type corresponding
    /// to the type parameter!
    pub fn new(buffer: Vec<T::Array>) -> Self {
        Self {
            items: buffer,
            _p: Default::default(),
        }
    }

    /// Deserialize a collection of RistrettoPoint-like types.
    /// Checks:
    /// * That the provided header matches [`T::HEADER`]()
    /// * That the provided length matches `self.buffer.len()`
    /// * That the provided checksum is correct
    ///
    /// Does NOT check:
    /// * That each element successfully decodes—use [`Self::iter_decoded`]() for that
    pub fn deserialize(src: &[u8]) -> Result<Self, DeserializeError> {
        // the minimum size is 13 (1 byte version + 4 bytes magic + 4 bytes length + no data + 4 bytes checksum)
        if src.len() < 13 {
            return Err(DeserializeError::InvalidSize(src.len()));
        }

        // first, split `src` into `checksummed_data` (everything but the last 4 bytes) and `checksum_bytes` (the last 4 bytes)
        // (it would be circular to checksum the checksum)
        let (bytes_to_checksum, checksum_bytes) = src.split_at(src.len() - 4);
        // then iteratively nibble `checksummed_data` away
        let (version_byte, rest) = bytes_to_checksum.split_at(1);
        let (magic_bytes, rest) = rest.split_at(4);
        let (length_bytes, data_bytes) = rest.split_at(4);

        // convert from slices to arrays
        let version_byte = <[u8; 1]>::try_from(version_byte).unwrap()[0];
        let magic_bytes: [u8; 4] = magic_bytes.try_into().unwrap();
        let length_bytes: [u8; 4] = length_bytes.try_into().unwrap();
        let checksum_bytes: [u8; 4] = checksum_bytes.try_into().unwrap();

        // check version
        if version_byte != VERSION {
            return Err(DeserializeError::InvalidVersion(version_byte, VERSION));
        }

        // check type field
        if magic_bytes != T::MAGIC {
            return Err(DeserializeError::WrongMagic(magic_bytes, T::MAGIC));
        }

        // check length is correct
        let length = u32::from_le_bytes(length_bytes);
        if (length as usize).checked_mul(T::SIZE) != Some(data_bytes.len()) {
            return Err(DeserializeError::WrongLength(length, data_bytes.len()));
        }

        // check the checksum
        let given_checksum = u32::from_le_bytes(checksum_bytes);
        let calculated_checksum = crc32fast::hash(bytes_to_checksum);
        if given_checksum != calculated_checksum {
            return Err(DeserializeError::WrongChecksum(
                given_checksum,
                calculated_checksum,
            ));
        }

        // finally, load the data
        let buffer = data_bytes
            .chunks_exact(T::SIZE)
            .map(|chunk| chunk.try_into().ok().unwrap())
            .collect();
        Ok(Self::new(buffer))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.len_bytes());

        // add header
        v.extend_from_slice(&[VERSION]);
        v.extend_from_slice(&T::MAGIC);
        v.extend_from_slice(&u32::to_le_bytes(self.items.len().try_into().unwrap()));

        // add encoded items
        for chunk in self.iter_encoded() {
            v.extend_from_slice(chunk.as_ref());
        }

        // add checksum
        let checksum = crc32fast::hash(&v[..]);
        v.extend_from_slice(&checksum.to_le_bytes());

        // sanity check
        assert_eq!(v.len(), self.len_bytes());

        v
    }

    pub fn encoded_items(&self) -> &[T::Array] {
        &self.items
    }

    /// Iterate the (potentially invalid, if this was deserialized but not decoded)
    /// encodings of `T`
    pub fn iter_encoded(&self) -> impl Iterator<Item = &T::Array> {
        self.items.iter()
    }

    /// Iterate the decoded `T`s, potentially encountering decoding errors.
    pub fn iter_decoded(
        &self,
    ) -> impl Iterator<Item = Result<T, <T as TryFrom<T::Array>>::Error>> + '_ {
        self.iter_encoded()
            .map(|encoded| (*encoded).clone().try_into())
    }

    /// Returns the number of *elements* in `self` (not the byte length)
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns the length in bytes of `self` (`self.len() * 32 + 13`)
    pub fn len_bytes(&self) -> usize {
        // header + checksum is an extra 13 bytes
        self.len() * T::SIZE + 13
    }

    /// Returns whether `self` is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: PackableRistretto> serde::Serialize for PackedRistrettos<T> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_bytes(&self.serialize())
    }
}

impl<'de, T: PackableRistretto> serde::Deserialize<'de> for PackedRistrettos<T> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes: &[u8] = serde::Deserialize::deserialize(d)?;
        Self::deserialize(bytes).map_err(D::Error::custom)
    }
}

impl<T: PackableRistretto> From<Vec<T::Array>> for PackedRistrettos<T> {
    fn from(value: Vec<T::Array>) -> Self {
        Self::new(value)
    }
}

impl<T: PackableRistretto, A: Into<T::Array>> FromIterator<A> for PackedRistrettos<T> {
    fn from_iter<I: IntoIterator<Item = A>>(iter: I) -> Self {
        Self::new(iter.into_iter().map(|a| a.into()).collect())
    }
}

impl From<&QueryStateSet> for PackedRistrettos<Query> {
    fn from(value: &QueryStateSet) -> Self {
        value.queries().collect()
    }
}

// this impl conflicts
// with `From` for `Vec` of arrays
// pining for `default`
//
// (https://github.com/rust-lang/rfcs/pull/1210)
//
// impl<T: PackableRistretto, I: IntoIterator<Item = T>> From<I> for PackedRistrettos<T> {
//     fn from(value: I) -> Self {
//         Self::from_iter(value)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck::{quickcheck, Arbitrary, Gen};

    fn assert_roundtrips<T: PackableRistretto + std::cmp::PartialEq + std::fmt::Debug>(
        p: PackedRistrettos<T>,
    ) {
        let se = p.serialize();
        let de = PackedRistrettos::<T>::deserialize(&se).unwrap();

        assert_eq!(
            p,
            de,
            "did not roundtrip:\nbefore:{p:?}\nafter:{de:?}\nserialized: len = {}, data = {:?}",
            se.len(),
            se
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct Dummy([u8; 32]);

    impl TryFrom<[u8; 32]> for Dummy {
        type Error = std::convert::Infallible;

        fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
            Ok(Self(value))
        }
    }

    impl From<Dummy> for [u8; 32] {
        fn from(val: Dummy) -> Self {
            val.0
        }
    }

    impl PackableRistretto for Dummy {
        type Array = [u8; 32];
        const MAGIC: [u8; 4] = *b"DUMB";
    }

    #[test]
    fn empty_roundtrips() {
        assert_roundtrips(PackedRistrettos::<Dummy>::new(vec![]));
    }

    #[test]
    fn empty_len() {
        assert_eq!(PackedRistrettos::<Dummy>::new(vec![]).len(), 0);
        assert_eq!(PackedRistrettos::<Dummy>::new(vec![]).len_bytes(), 13);
        assert_eq!(PackedRistrettos::<Dummy>::new(vec![]).serialize().len(), 13);
    }

    #[test]
    fn one_item_roundtrips() {
        assert_roundtrips(PackedRistrettos::<Dummy>::new(vec![[0; 32]]));
        assert_eq!(PackedRistrettos::<Dummy>::new(vec![[0; 32]]).len(), 1);
        assert_eq!(
            PackedRistrettos::<Dummy>::new(vec![[0; 32]]).len_bytes(),
            32 + 13
        );
        assert_eq!(
            PackedRistrettos::<Dummy>::new(vec![[0; 32]])
                .serialize()
                .len(),
            32 + 13
        );
    }

    impl Arbitrary for Dummy {
        fn arbitrary(g: &mut Gen) -> Self {
            Self([0_u8; 32].map(|_| u8::arbitrary(g)))
        }
    }

    impl Arbitrary for PackedRistrettos<Dummy> {
        fn arbitrary(g: &mut Gen) -> Self {
            let dummies = Vec::<Dummy>::arbitrary(g);
            dummies.into_iter().collect()
        }
    }

    quickcheck! {
        fn qc_roundtrips(p: PackedRistrettos<Dummy>) -> bool {
            assert_roundtrips(p);
            true
        }

        fn qc_len(p: PackedRistrettos<Dummy>) -> bool {
            let se = p.serialize();
            se.len() == p.len_bytes()
        }
    }

    /// Fix the checksum of the twiddled data for the invalid tests, so they fail for
    /// non-incorrect-checksum reasons—since we want to test that the other error paths
    /// work in case of incorrect serialization without relying on the checksum check
    /// coming last
    fn fix_checksum(b: &mut [u8]) {
        let checksum_start = b.len() - 4;
        let checksum = crc32fast::hash(&b[..checksum_start]);
        b[checksum_start..].copy_from_slice(&checksum.to_le_bytes());
    }

    #[test]
    fn no_deserialize_wrong_version() {
        let mut b = PackedRistrettos::<Dummy>::new(vec![]).serialize();
        b[0] = 255;
        fix_checksum(&mut b);
        assert_eq!(
            PackedRistrettos::<Dummy>::deserialize(&b),
            Err(DeserializeError::InvalidVersion(255, 1)),
        );
    }

    #[test]
    fn no_deserialize_wrong_magic() {
        let ser = PackedRistrettos::<Dummy>::new(vec![]).serialize();

        let incorrect_magics = [b"XUMB", b"DXMB", b"DUXB", b"DUMX"];
        for incorrect_magic in incorrect_magics {
            let mut ser = ser.clone();
            ser[1..5].copy_from_slice(incorrect_magic);

            fix_checksum(&mut ser);

            assert_eq!(
                PackedRistrettos::<Dummy>::deserialize(&ser),
                Err(DeserializeError::WrongMagic(*incorrect_magic, Dummy::MAGIC)),
            );
        }
    }

    #[test]
    fn no_deserialize_wrong_length_empty() {
        let mut b = PackedRistrettos::<Dummy>::new(vec![]).serialize();
        b[5] = 1;
        fix_checksum(&mut b);
        assert_eq!(
            PackedRistrettos::<Dummy>::deserialize(&b),
            Err(DeserializeError::WrongLength(1, 0)),
        );
    }

    #[test]
    fn no_deserialize_wrong_length_nonempty() {
        let mut b = PackedRistrettos::<Dummy>::new(vec![[0_u8; 32]]).serialize();
        b[5] = 0;
        fix_checksum(&mut b);
        assert_eq!(
            PackedRistrettos::<Dummy>::deserialize(&b),
            Err(DeserializeError::WrongLength(0, 32)),
        );
    }

    quickcheck! {
        fn qc_no_deserialize_wrong_checksum(pr: PackedRistrettos::<Dummy>, index: usize) -> bool {
            let mut ser = pr.serialize();
            let index = index % ser.len();
            ser[index] = ser[index].wrapping_add(1);
            // might be a non-checksum related error if we corrupted, e.g., the length field
            PackedRistrettos::<Dummy>::deserialize(&ser).is_err()
        }
    }
}
