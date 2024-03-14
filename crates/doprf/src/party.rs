// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fmt::Display, num::NonZeroU32, str::FromStr};

use curve25519_dalek::scalar::Scalar;
use rasn::prelude::fields::{Field, Fields};
use rasn::types::Integer;
use rasn::{de::Error, AsnType};
use serde::{Deserialize, Serialize};

use crate::lagrange::{lagrange_coefficient_at_zero, lagrange_coefficients_at_zero};

/// Keyserver id corresponds to the x coordinate of the keyserver's keyshare
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct KeyserverId(NonZeroU32);

impl KeyserverId {
    pub fn to_scalar(&self) -> Scalar {
        Scalar::from(self.0.get())
    }

    pub fn as_u32(&self) -> u32 {
        self.into()
    }
}

impl From<&KeyserverId> for u32 {
    fn from(value: &KeyserverId) -> Self {
        value.0.get()
    }
}

impl TryFrom<u32> for KeyserverId {
    type Error = InvalidKeyserverId;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        NonZeroU32::new(value)
            .map(KeyserverId)
            .ok_or(InvalidKeyserverId)
    }
}

impl rasn::Encode for KeyserverId {
    fn encode_with_tag_and_constraints<E: rasn::prelude::Encoder>(
        &self,
        encoder: &mut E,
        tag: rasn::Tag,
        _: rasn::prelude::Constraints,
    ) -> Result<(), E::Error> {
        encoder.encode_sequence::<KeyserverId, _>(tag, |encoder| self.0.get().encode(encoder))?;
        Ok(())
    }
}

impl rasn::Decode for KeyserverId {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: rasn::Tag,
        _: rasn::types::Constraints,
    ) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |decoder| {
            let value = u32::decode(decoder)?;
            NonZeroU32::new(value)
                .map(KeyserverId)
                .ok_or_else(|| D::Error::custom("Zero value not allowed in KeyserverId"))
        })
    }
}

impl rasn::AsnType for KeyserverId {
    const TAG: rasn::prelude::Tag = rasn::Tag::SEQUENCE;
}

// Required to ensure that the ASN.1 encoding is an integer within a sequence
impl rasn::types::Constructed for KeyserverId {
    const FIELDS: Fields =
        Fields::from_static(&[Field::new_required(Integer::TAG, Integer::TAG_TREE)]);
}

impl FromStr for KeyserverId {
    type Err = InvalidKeyserverId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>()
            .map_err(|_| InvalidKeyserverId)?
            .try_into()
            .map_err(|_| InvalidKeyserverId)
    }
}

impl Display for KeyserverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
pub struct InvalidKeyserverId;

impl Display for InvalidKeyserverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Keyserver id must be a positive integer")
    }
}

impl std::error::Error for InvalidKeyserverId {}

/// Set of keyserver ids which will participate in the database membership protocol.
/// This set's size must correspond to the number of keyholders required to evaluate the DOPRF - it cannot contain any more or less.
// TODO: Add check that the set size is correct.
#[derive(Debug, Clone)]
pub struct KeyserverIdSet {
    sorted_keyserver_ids: Vec<KeyserverId>,
}

impl KeyserverIdSet {
    /// Lagrange coefficients corresponding to all keyserver ids within the set.
    /// Can be applied to the corresponding keyshares, and combined to evaluate the DOPRF.
    pub fn langrange_coefficients(&self) -> impl Iterator<Item = Scalar> {
        let x_coords: Vec<Scalar> = self
            .sorted_keyserver_ids
            .iter()
            .map(|id| id.to_scalar())
            .collect();
        lagrange_coefficients_at_zero(&x_coords)
    }

    /// Lagrange coefficient corresponding to the supplied keyserver id, with respect to the other ids in the set.
    /// Can be applied to the corresponding keyshare and, when combined with contributions from other keyservers within the set,
    /// enables the evaluation of the DOPRF.
    pub fn langrange_coefficient_for_id(&self, id: &KeyserverId) -> Scalar {
        let x_i = id.to_scalar();
        let x_coords: Vec<Scalar> = self
            .sorted_keyserver_ids
            .iter()
            .map(|id| id.to_scalar())
            .collect();
        lagrange_coefficient_at_zero(x_i, &x_coords)
    }

    pub fn iter(&self) -> impl Iterator<Item = &KeyserverId> {
        self.sorted_keyserver_ids.iter()
    }

    pub fn len(&self) -> usize {
        self.sorted_keyserver_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug)]
pub struct KeyserverIdSetParseError;

impl Display for KeyserverIdSetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "keyserver id set should be a comma separated list of non-zero ints"
        )
    }
}

impl FromStr for KeyserverIdSet {
    type Err = KeyserverIdSetParseError;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let values: Vec<u32> = string
            .split(',')
            .map(|s| s.trim().parse())
            .collect::<Result<_, _>>()
            .map_err(|_| KeyserverIdSetParseError)?;

        let keyserver_ids: Vec<KeyserverId> = values
            .into_iter()
            .map(KeyserverId::try_from)
            .collect::<Result<_, _>>()
            .map_err(|_| KeyserverIdSetParseError)?;

        Ok(KeyserverIdSet::from_iter(keyserver_ids))
    }
}

impl Display for KeyserverIdSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let list: Vec<String> = self
            .sorted_keyserver_ids
            .iter()
            .map(|id| id.to_string())
            .collect();
        write!(f, "{}", list.join(","))
    }
}

impl From<Vec<KeyserverId>> for KeyserverIdSet {
    fn from(mut v: Vec<KeyserverId>) -> Self {
        // Warning: removing the sorting of the ids could break screening!
        v.sort_unstable();
        Self {
            sorted_keyserver_ids: v,
        }
    }
}

impl FromIterator<KeyserverId> for KeyserverIdSet {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = KeyserverId>,
    {
        let ids: Vec<KeyserverId> = iter.into_iter().collect();
        ids.into()
    }
}
