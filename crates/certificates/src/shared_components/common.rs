// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::marker::PhantomData;
use std::{
    fmt,
    fmt::{Debug, Display},
    str::FromStr,
};

use rand::{RngCore, rngs::OsRng};
use rasn::{Decode, Encode, de::Error, types::*};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;
use time::Duration;

use crate::asn_encode_as_octet_string_impl;
use crate::key::signing::{PublicKey, Signature};
use crate::utility::now_utc;

/// Implemented by components of certificates and tokens.
pub trait VersionedComponent {
    const COMPONENT_NAME: &'static str;
    const ITERATION: u16;
    fn revision() -> String {
        Self::COMPONENT_NAME.to_string() + &Self::ITERATION.to_string()
    }
}
/// `ComponentVersionGuard` ensures that serialized or encoded components cannot be
/// deserialized or decoded as a later iteration of that component, or as a different
/// component with the same fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
// tsgen
pub struct ComponentVersionGuard<V: VersionedComponent>(PhantomData<V>);

impl<V: VersionedComponent> ComponentVersionGuard<V> {
    pub(crate) fn new() -> Self {
        Self(PhantomData::<V>)
    }
}

impl<V: VersionedComponent> Serialize for ComponentVersionGuard<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&V::revision())
    }
}

impl<'de, V: VersionedComponent> Deserialize<'de> for ComponentVersionGuard<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = String::deserialize(deserializer)?;
        let expected = V::revision();
        if version == expected {
            Ok(ComponentVersionGuard(PhantomData))
        } else {
            Err(serde::de::Error::custom(format!(
                "unexpected version found: {version}, expected {expected}",
            )))
        }
    }
}

impl<V: VersionedComponent> AsnType for ComponentVersionGuard<V> {
    const TAG: rasn::Tag = Tag::UTF8_STRING;
}

impl<V: VersionedComponent> Encode for ComponentVersionGuard<V> {
    fn encode_with_tag_and_constraints<E: rasn::Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::Constraints,
    ) -> Result<(), E::Error> {
        V::revision().encode_with_tag_and_constraints(encoder, tag, constraints)
    }
}

impl<V: VersionedComponent> Decode for ComponentVersionGuard<V> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::Constraints,
    ) -> Result<Self, D::Error> {
        let version = Utf8String::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        let expected = V::revision();
        if version == expected {
            Ok(ComponentVersionGuard(PhantomData))
        } else {
            Err(D::Error::custom(format!(
                "unexpected version found: {}, expected {}",
                version, expected
            )))
        }
    }
}

/// Id is a unique 128-bit value, stored as 16 octets.
/// Uniqueness is not guaranteed, however it can be assumed that a collision would be extremely unlikely.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, SerializeDisplay, DeserializeFromStr,
)]
// tsgen
pub struct Id([u8; Self::LEN]);

impl Id {
    const LEN: usize = 16;
    pub fn new_random() -> Self {
        let mut bytes = [0u8; Self::LEN];
        OsRng.fill_bytes(&mut bytes);
        Id(bytes)
    }
}

impl From<[u8; Id::LEN]> for Id {
    fn from(value: [u8; Id::LEN]) -> Self {
        Self(value)
    }
}

impl From<Id> for [u8; Id::LEN] {
    fn from(value: Id) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

asn_encode_as_octet_string_impl!(Id, Id::LEN);

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Error)]
#[error("could not parse id from hex value")]
pub struct ParseIdError;

impl FromStr for Id {
    type Err = ParseIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; Self::LEN] = hex::decode(s)
            .map_err(|_| ParseIdError)?
            .try_into()
            .map_err(|_| ParseIdError)?;
        Ok(Id(bytes))
    }
}

impl Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Id").field(&self.to_string()).finish()
    }
}

#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
)]
// tsgen
#[rasn(automatic_tags)]
pub struct Attachment {
    pub name: String,
    pub contents: Vec<u8>,
}

impl Display for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ({} bytes)", self.name, self.contents.len())
    }
}

#[derive(
    AsnType,
    Debug,
    Encode,
    Decode,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Default,
    Serialize,
    Deserialize,
)]
// tsgen
#[rasn(automatic_tags)]
pub struct Description {
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone_number: Option<String>,
    pub orcid: Option<String>,
}

impl Description {
    pub fn with_name<T: Into<String>>(mut self, name: T) -> Self {
        self.name = Some(name.into());
        self
    }
    pub fn with_email<T: Into<String>>(mut self, email: T) -> Self {
        self.email = Some(email.into());
        self
    }
    pub fn with_phone_number<T: Into<String>>(mut self, phone_number: T) -> Self {
        self.phone_number = Some(phone_number.into());
        self
    }
    pub fn with_orcid<T: Into<String>>(mut self, orcid: T) -> Self {
        self.orcid = Some(orcid.into());
        self
    }
}

impl Display for Description {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<&str> = [&self.name, &self.email, &self.phone_number, &self.orcid]
            .into_iter()
            .filter_map(|x| x.as_deref())
            .collect();

        if !parts.is_empty() {
            write!(f, "{}", parts.join(", "))?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
// tsgen
pub enum OutsideValidityPeriod {
    Expired,
    NotYetValid,
}

/// Holds expiry date of the certificate
#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
// tsgen
#[rasn(automatic_tags)]
pub struct Expiration {
    pub not_valid_before: i64,
    pub not_valid_after: i64,
}

/// An abstract interface for getting a "current time".
///
/// Usually, this is [SystemClock], which returns the system's current time.
///
/// When verifying a result from verifiable screening, a [FixedClock] is used,
/// set to the time of the screening result. This way, the verifier cert from
/// the result can be used even if it is expired, as long as it was valid when
/// the result was generated.
pub trait Clock {
    /// Return the current Unix timestamp in seconds.
    fn unix_timestamp(&self) -> i64;
}

/// A [Clock] that reports the current system time.
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_timestamp(&self) -> i64 {
        now_utc().unix_timestamp()
    }
}

/// A [Clock] that is fixed to a constant timestamp.
pub struct FixedClock {
    pub unix_timestamp: i64,
}

impl Clock for FixedClock {
    fn unix_timestamp(&self) -> i64 {
        self.unix_timestamp
    }
}

impl Expiration {
    pub const DEFAULT_DAYS: i64 = 28;

    /// Validate this [Expiration] using the given [Clock] (by checking whether
    /// the Clock's current time is within the validity range).
    pub fn validate(&self, clock: &impl Clock) -> Result<(), OutsideValidityPeriod> {
        let now = clock.unix_timestamp();
        if now < self.not_valid_before {
            Err(OutsideValidityPeriod::NotYetValid)
        } else if now > self.not_valid_after {
            Err(OutsideValidityPeriod::Expired)
        } else {
            Ok(())
        }
    }

    /// Create an [Expiration] valid from now until `days` days in the future,
    /// using the system clock.
    pub fn expiring_in_days(days: i64) -> Result<Self, ExpirationError> {
        Self::expiring_in_days_from(&SystemClock, days)
    }

    /// Create an [Expiration] valid from the given clock's current time until
    /// `days` days later.
    pub fn expiring_in_days_from(clock: &impl Clock, days: i64) -> Result<Self, ExpirationError> {
        if days <= 0 {
            return Err(ExpirationError::InsufficientDaysValid);
        }
        Ok(Self::unchecked_expiring_in_days_from(clock, days))
    }

    fn unchecked_expiring_in_days_from(clock: &impl Clock, days: i64) -> Self {
        let start = clock.unix_timestamp();
        let end = start + Duration::days(days).whole_seconds();
        Self {
            not_valid_before: start,
            not_valid_after: end,
        }
    }

    /// Compute how many days from now the validity period lasts, rounding up.
    /// If the token is expired, the result is 0 rather than negative.
    pub fn days_until_expiry(&self, clock: &impl Clock) -> i64 {
        let now = clock.unix_timestamp();
        let seconds_remaining = self.not_valid_after - now;
        const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

        // div_ceil is experimental: https://github.com/rust-lang/rust/issues/88581
        // We'll simulate `a.div_ceil(b)` using `(a + (b - 1)) / b`.
        // let days_remaining = seconds_remaining.div_ceil(SECONDS_PER_DAY);
        let days_remaining = (seconds_remaining + (SECONDS_PER_DAY - 1)) / SECONDS_PER_DAY;

        days_remaining.max(0)
    }
}

impl Default for Expiration {
    fn default() -> Self {
        Self::unchecked_expiring_in_days_from(&SystemClock, Self::DEFAULT_DAYS)
    }
}

#[derive(Debug, Error, PartialEq)]
// This is an enum as I'm assuming we'll also have max values for how long a certificate/token is valid.
pub enum ExpirationError {
    #[error("must be valid for one day or longer")]
    InsufficientDaysValid,
}

/// We can't assume that a future certificate will use the same identity fields as
/// its issuer. For this reason we use `CompatibleIdentity` to define a certificate's issuer.
/// While the identity description may prove useful as a human readable value,
/// the only field of real importance is the issuer's public key.
#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
// tsgen
#[rasn(automatic_tags)]
pub struct CompatibleIdentity {
    pub pk: PublicKey,
    pub desc: String,
}

#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
// tsgen
#[rasn(automatic_tags)]
pub struct Signed<L> {
    pub(crate) data: L,
    pub(crate) signature: Signature,
}

impl<L> Signed<L> {
    pub fn new(data: L, signature: Signature) -> Self {
        Self { data, signature }
    }
}

#[cfg(all(test, feature = "cert_tests"))]
mod tests {
    use crate::asn::ToASN1DerBytes;

    use super::*;
    #[test]
    fn id_der_encoding_is_expected_length() {
        let id = Id::new_random();
        let encoded = id.to_der().unwrap();
        assert_eq!(encoded.len(), Id::LEN + 2);
    }

    #[test]
    fn test_system_and_fixed_clock() {
        let expiration = Expiration::expiring_in_days(3).unwrap();
        assert_eq!(expiration.validate(&SystemClock), Ok(()));

        let now_clock = FixedClock {
            unix_timestamp: SystemClock.unix_timestamp() + 60,
        };
        assert_eq!(expiration.validate(&now_clock), Ok(()));

        let past_clock = FixedClock {
            unix_timestamp: SystemClock.unix_timestamp() - 1_000_000,
        };
        assert_eq!(
            expiration.validate(&past_clock),
            Err(OutsideValidityPeriod::NotYetValid)
        );

        let future_clock = FixedClock {
            unix_timestamp: SystemClock.unix_timestamp() + 1_000_000,
        };
        assert_eq!(
            expiration.validate(&future_clock),
            Err(OutsideValidityPeriod::Expired)
        );
    }
}
