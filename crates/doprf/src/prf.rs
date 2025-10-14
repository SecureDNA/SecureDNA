// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hex::FromHexError;
#[cfg(any(feature = "centralized_keygen", test))]
use rand::{CryptoRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha3::Sha3_512;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[cfg(any(feature = "centralized_keygen", test))]
use crate::lagrange::evaluate_lagrange_polynomial;
pub use crate::queryset::QueryError;

/// The probability that a malicious party could evade active security is 2^(-SECURITY_PARAMETER).
/// Values of 4N+2 for N=0,1,... will maximise security vs speed.
/// A value of 18 entails a 2.5% performance reduction.
pub const SECURITY_PARAMETER: u8 = 18;

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
)]
#[repr(transparent)]
pub struct CompressedQuery([u8; 32]);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Query(RistrettoPoint);

impl Query {
    #[cfg(feature = "centralized_keygen")]
    pub fn hash_from_string(seq: &str) -> Self {
        Self(RistrettoPoint::hash_from_bytes::<Sha3_512>(seq.as_bytes()))
    }
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
)]
#[repr(transparent)]
pub struct CompressedHashPart([u8; 32]);

/// Response from a keyholder: (H(x)^r)^{f(i)*c_i}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HashPart(RistrettoPoint);

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
)]
#[repr(transparent)]
pub struct CompressedCompletedHashValue([u8; 32]);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CompletedHashValue(RistrettoPoint);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct KeyShare(Scalar);

impl KeyShare {
    pub fn apply(&self, q: Query) -> HashPart {
        HashPart::from_rp(q.to_rp() * self.0)
    }

    pub fn apply_query_and_lagrange_coefficient(&self, q: Query, c: &Scalar) -> HashPart {
        HashPart::from_rp(c * self.0 * q.to_rp())
    }

    pub fn multiply_by_rp(&self, point: RistrettoPoint) -> RistrettoPoint {
        self.0 * point
    }

    /// Multiplication by the Ristretto base point
    pub fn multiply_by_base(&self) -> RistrettoPoint {
        RistrettoPoint::mul_base(&self.0)
    }

    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        KeyShare(Scalar::random(rng))
    }
}

/// Generates keyshares based on a minimum threshold and total number of shares
#[cfg(any(feature = "centralized_keygen", test))]
pub fn generate_keyshares(
    secret_key: &KeyShare,
    required_keyholders: NonZeroU32,
    num_keyholders: NonZeroU32,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<KeyShare>, UnreachableQuorumError> {
    if num_keyholders < required_keyholders {
        return Err(UnreachableQuorumError {
            required_keyholders,
            num_keyholders,
        });
    }
    let mut control_points = vec![secret_key.0];
    control_points.extend((1..required_keyholders.get()).map(|_| Scalar::random(rng)));
    let keyshares = (1..=num_keyholders.get())
        .map(|x| {
            let cached = control_points.get(x as usize).copied();
            let lagrange_curve_at_x =
                cached.unwrap_or_else(|| evaluate_lagrange_polynomial(&control_points, x));
            KeyShare(lagrange_curve_at_x)
        })
        .collect();
    Ok(keyshares)
}

#[derive(Debug, Clone)]
pub struct UnreachableQuorumError {
    required_keyholders: NonZeroU32,
    num_keyholders: NonZeroU32,
}

impl fmt::Display for UnreachableQuorumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let num_ks = self.num_keyholders;
        let quorum_size = self.required_keyholders;
        write!(f, "{num_ks} keyholders can't reach quorum of {quorum_size}")
    }
}

impl Error for UnreachableQuorumError {}

#[derive(Debug, Clone)]
pub enum DecodeError {
    HexError(FromHexError),
    InvalidRistrettoPoint,
    InvalidScalar,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HexError(fhe) => format!("Could not decode hexadecimal: {}", fhe),
            Self::InvalidRistrettoPoint => "Value was not a valid Ristretto point".to_string(),
            Self::InvalidScalar => "Value was not a valid Ristretto Scalar".to_string(),
        };
        write!(f, "{}", s)
    }
}

impl Error for DecodeError {}

impl From<Scalar> for KeyShare {
    fn from(value: Scalar) -> Self {
        Self(value)
    }
}

impl fmt::Display for KeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for KeyShare {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(DecodeError::HexError)?
            .try_into()
            .map_err(|_| DecodeError::InvalidScalar)?;
        if let Some(scalar) = Scalar::from_canonical_bytes(bytes).into() {
            Ok(KeyShare(scalar))
        } else {
            Err(DecodeError::InvalidScalar)
        }
    }
}

impl<'de> Deserialize<'de> for KeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

// In some sense we ought to be able to use blanket impls for these, and an
// `IsRistrettoPoint` trait. But in fact Rust doesn't know that a private
// trait can't have nonlocal impls, so it won't let us do things that way.
#[macro_export]
macro_rules! impls_for_ristretto_point {
    ($ctype: ident, $utype: ident) => {
        impl $ctype {
            pub fn decompress(&self) -> Result<$utype, DecodeError> {
                CompressedRistretto(self.0)
                    .decompress()
                    .map($utype)
                    .ok_or(DecodeError::InvalidRistrettoPoint)
            }

            pub fn from_rp(point: RistrettoPoint) -> Self {
                Self(point.compress().0)
            }

            pub fn to_rp(&self) -> Result<RistrettoPoint, DecodeError> {
                CompressedRistretto(self.0)
                    .decompress()
                    .ok_or(DecodeError::InvalidRistrettoPoint)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl From<&$ctype> for [u8; 32] {
            fn from(compressed: &$ctype) -> Self {
                compressed.0
            }
        }

        impl From<$ctype> for [u8; 32] {
            fn from(compressed: $ctype) -> Self {
                compressed.0
            }
        }

        impl From<&[u8; 32]> for $ctype {
            fn from(bytes: &[u8; 32]) -> Self {
                Self(*bytes)
            }
        }

        impl From<[u8; 32]> for $ctype {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl $utype {
            pub fn from_rp(point: RistrettoPoint) -> Self {
                Self(point)
            }

            pub fn to_rp(self) -> RistrettoPoint {
                self.0
            }

            pub fn compress(&self) -> $ctype {
                $ctype::from_rp(self.0)
            }

            fn try_from_buf(bytes: &[u8; 32]) -> Result<Self, DecodeError> {
                $ctype::from(bytes).decompress()
            }

            fn display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(<[u8; 32]>::from(self)))
            }

            fn from_ristretto_str(s: &str) -> Result<Self, DecodeError> {
                let bytes = hex::decode(s)
                    .map_err(DecodeError::HexError)?
                    .try_into()
                    .map_err(|_| DecodeError::InvalidRistrettoPoint)?;
                Self::try_from_buf(&bytes)
            }
        }
        impl FromStr for $utype {
            type Err = DecodeError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_ristretto_str(s)
            }
        }
        impl fmt::Display for $utype {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.display(f)
            }
        }
        impl From<&$utype> for [u8; 32] {
            fn from(t: &$utype) -> Self {
                t.compress().into()
            }
        }
        impl From<$utype> for [u8; 32] {
            fn from(t: $utype) -> Self {
                (&t).into()
            }
        }
        impl TryFrom<&[u8; 32]> for $utype {
            type Error = DecodeError;
            fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
                Self::try_from_buf(bytes)
            }
        }
        impl TryFrom<[u8; 32]> for $utype {
            type Error = DecodeError;
            fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        impl Serialize for $utype {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&format!("{}", &self))
            }
        }

        impl<'de> Deserialize<'de> for $utype {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                FromStr::from_str(&s).map_err(de::Error::custom)
            }
        }

        impl $utype {
            /// This method is marked as only for tests, because it's not needed for the main
            /// protocol, and there's no reason to be doing it. We only need it to generate
            /// arbitrary values during testing.
            pub fn hash_from_bytes_for_tests_only(bytes: &[u8]) -> $utype {
                let rp = RistrettoPoint::hash_from_bytes::<Sha3_512>(bytes);
                $utype::from_rp(rp)
            }
        }
    };
}

impls_for_ristretto_point!(CompressedQuery, Query);
impls_for_ristretto_point!(CompressedHashPart, HashPart);
impls_for_ristretto_point!(CompressedCompletedHashValue, CompletedHashValue);

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[cfg(feature = "centralized_keygen")]
    #[test]
    fn generate_keyshares_requires_enough_keyholders_for_quorum() {
        let rng = &mut OsRng;
        let secret = Scalar::random(rng).into();
        let cases = [(2, 1), (3, 2), (3, 1), (4, 2), (5, 4), (5, 1), (10, 1)];
        for (required_keyholders, num_keyholders) in cases {
            let required_keyholders = NonZeroU32::new(required_keyholders).unwrap();
            let num_keyholders = NonZeroU32::new(num_keyholders).unwrap();
            if generate_keyshares(&secret, required_keyholders, num_keyholders, rng).is_ok() {
                panic!(
                    "Shouldn't have generated only {num_keyholders} keyshares \
                        when {required_keyholders} are needed for a quorum"
                );
            }
        }
    }
}
