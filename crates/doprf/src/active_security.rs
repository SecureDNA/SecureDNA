// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::hash::Hash;
use std::num::NonZeroU32;
use std::str::FromStr;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::rngs::OsRng;
use serde::{de, ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};
use sha3::Sha3_512;

use crate::lagrange::evaluate_lagrange_polynomial;
use crate::party::KeyserverId;
use crate::party::KeyserverIdSet;
use crate::prf::DecodeError;
use crate::prf::KeyShare;

/// Validation target used in database membership protocol.
/// Acts as a checksum for verifying the keyserver's responses, ensuring correct evaluation of the PRF.
// Default is implemented here to preserve functionality in 'incorporate_responses_and_hash'
// function where QueryStateSet's ownership is temporarily changed.
// However this shouldn't really have a default implementation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Target(RistrettoPoint);

/// Provides a commitment to a secret scalar value, without revealing it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, std::hash::Hash)]
pub struct Commitment(CompressedRistretto);

impl Commitment {
    // Commitments are created using the generator point for our chosen curve.
    pub fn from_keyshare(keyshare: &KeyShare) -> Self {
        let point = keyshare.multiply_by_base();
        Commitment::from_rp(point)
    }
}

/// Creates a `RandomizedTarget`for each screening, used to ensure correct evaluation
/// of the DOPRF and identify which keyservers are responsible for an incorrect result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveSecurityKey(Vec<RistrettoPoint>);

impl ActiveSecurityKey {
    pub fn from_commitments(commitments: impl IntoIterator<Item = Commitment>) -> Self {
        Self(commitments.into_iter().map(|c| c.to_rp()).collect())
    }

    /// To validate the keyserver responses we create a target unknown to the keyservers.
    pub fn randomized_target(&self) -> RandomizedTarget {
        let random_modifier = Scalar::random(&mut OsRng);
        let target = Target(self.0[0] * random_modifier);

        RandomizedTarget {
            random_modifier,
            target,
            commitments: self.0.clone(),
        }
    }

    /// The active security key supports a quorum that is equal to the number of commitments it holds internally
    pub fn supported_quorum(&self) -> u32 {
        self.0.len() as u32
    }

    #[cfg(test)]
    pub fn from_secret_and_keyshares<'a>(
        secret: &KeyShare,
        keyshares: impl IntoIterator<Item = &'a KeyShare>,
        keyholders_required: NonZeroU32,
    ) -> Result<Self, InvalidSecretAndKeyshareInput> {
        let commitments =
            commitments_from_secret_and_keyshares(secret, keyshares, keyholders_required)?;
        Ok(Self::from_commitments(commitments))
    }
}

// Keyshares must correspond to keyserver ids 1 to t+1
pub fn commitments_from_secret_and_keyshares<'a>(
    secret: &KeyShare,
    keyshares: impl IntoIterator<Item = &'a KeyShare>,
    keyholders_required: NonZeroU32,
) -> Result<Vec<Commitment>, InvalidSecretAndKeyshareInput> {
    let keyholders_required = keyholders_required.get() as usize;
    let mut secrets = Vec::new();
    secrets.push(*secret);
    secrets.extend(keyshares);

    // Check we have enough information to calculate and verify active security key
    if secrets.len() < keyholders_required {
        return Err(InvalidSecretAndKeyshareInput);
    }

    // Calculates commitments using shares at indices 0 to t
    let commitments: Vec<RistrettoPoint> = secrets
        .iter()
        .take(keyholders_required)
        .map(|ks| ks.multiply_by_base())
        .collect();

    // check against commitment corresponding to index t+1
    let p = evaluate_lagrange_polynomial(&commitments, keyholders_required as u32);
    let p_from_keyshare = secrets[keyholders_required].multiply_by_base();
    if p.compress().as_bytes() != p_from_keyshare.compress().as_bytes() {
        return Err(InvalidSecretAndKeyshareInput);
    }

    Ok(commitments.into_iter().map(Commitment::from_rp).collect())
}

struct RistrettoPointWrapper(RistrettoPoint);

impl Serialize for RistrettoPointWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64_helper::serialize(
            serializer,
            base64::engine::general_purpose::STANDARD,
            self.0.compress().as_bytes(),
        )
    }
}

impl<'de> Deserialize<'de> for RistrettoPointWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes =
            base64_helper::deserialize(deserializer, base64::engine::general_purpose::STANDARD)?;
        let decompressed = CompressedRistretto::from_slice(&bytes)
            .unwrap() // we can unwrap because we know the byte slice has the correct length
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("Invalid RistrettoPoint encoding found"))?;
        Ok(Self(decompressed))
    }
}

impl Serialize for ActiveSecurityKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for rp in &self.0 {
            seq.serialize_element(&RistrettoPointWrapper(*rp))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ActiveSecurityKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ActiveSecurityKeyVisitor;

        impl<'de> de::Visitor<'de> for ActiveSecurityKeyVisitor {
            type Value = ActiveSecurityKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of base64 encoded strings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut items = Vec::new();

                while let Some(wrapper) = seq.next_element::<RistrettoPointWrapper>()? {
                    items.push(wrapper.0);
                }

                Ok(ActiveSecurityKey(items))
            }
        }

        deserializer.deserialize_seq(ActiveSecurityKeyVisitor)
    }
}

impl Hash for ActiveSecurityKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for point in &self.0 {
            point.compress().hash(state);
        }
    }
}

#[derive(Debug)]
pub struct CommitmentCountError;

impl Error for CommitmentCountError {}

impl Display for CommitmentCountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "not enough commitments to create an active security key for the specified quorum"
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct InvalidSecretAndKeyshareInput;

impl Error for InvalidSecretAndKeyshareInput {}

impl Display for InvalidSecretAndKeyshareInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "could not calculate active security commitments from the secret and keyshares provided"
        )
    }
}

/// Randomised target is a modification of the established target
#[derive(Debug, Clone, Default)]
pub struct RandomizedTarget {
    random_modifier: Scalar,
    target: Target,
    commitments: Vec<RistrettoPoint>,
}

impl RandomizedTarget {
    pub fn get_checksum_point_for_validation(&self, point_sum: &RistrettoPoint) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT * self.random_modifier - point_sum
    }

    pub fn validate_responses(&self, verifier: &RistrettoPoint) -> bool {
        self.target.0 == *verifier
    }

    pub fn is_keyserver_response_valid(
        &self,
        keyservers: &KeyserverIdSet,
        keyserver_id: &KeyserverId,
        sum: &RistrettoPoint,
    ) -> bool {
        let coeff = keyservers.langrange_coefficient_for_id(keyserver_id);
        let verifier = evaluate_lagrange_polynomial(&self.commitments, keyserver_id.into());
        self.random_modifier * coeff * verifier == *sum
    }
}

impl Commitment {
    pub fn to_rp(self) -> RistrettoPoint {
        self.0.decompress().unwrap()
    }
}

impls_for_ristretto_point!(Commitment);

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use curve25519_dalek::Scalar;
    use rand::{seq::SliceRandom, thread_rng, Rng};

    use crate::{active_security::commitments_from_secret_and_keyshares, prf::generate_keyshares};

    use super::{ActiveSecurityKey, Commitment};

    #[test]
    fn can_generate_commitments_from_secret_and_keyshares() {
        let mut rng = thread_rng();
        let secret_key = Scalar::random(&mut rng).into();

        let keyholders_required = rng.gen_range(1..=10);
        let num_keyholders = rng.gen_range(keyholders_required..=keyholders_required + 5);

        let keyshares = generate_keyshares(
            &secret_key,
            NonZeroU32::new(keyholders_required).unwrap(),
            NonZeroU32::new(num_keyholders).unwrap(),
            &mut rng,
        )
        .unwrap();

        let result = commitments_from_secret_and_keyshares(
            &secret_key,
            &keyshares,
            NonZeroU32::new(keyholders_required).unwrap(),
        );
        assert!(result.is_ok());

        let commitment_count = result.unwrap().len();
        assert_eq!(commitment_count, keyholders_required as usize);
    }

    #[test]
    fn cannot_generate_commitments_from_mismatched_secret_and_keyshares() {
        let mut rng = thread_rng();
        let secret_key = Scalar::random(&mut rng).into();
        let incorrect_secret_key = Scalar::random(&mut rng).into();

        let keyholders_required = rng.gen_range(1..=10);
        let num_keyholders = rng.gen_range(keyholders_required..=keyholders_required + 5);

        let keyshares = generate_keyshares(
            &secret_key,
            NonZeroU32::new(keyholders_required).unwrap(),
            NonZeroU32::new(num_keyholders).unwrap(),
            &mut rng,
        )
        .unwrap();

        // use secret key that doesn't match keyshares
        commitments_from_secret_and_keyshares(
            &incorrect_secret_key,
            &keyshares,
            NonZeroU32::new(keyholders_required).unwrap(),
        )
        .expect_err(
            "should not be able to calculate commitments from mismatched secret and keyshares",
        );
    }

    #[test]
    fn cannot_generate_commitments_from_insufficient_keyshare_count() {
        let mut rng = thread_rng();
        let secret_key = Scalar::random(&mut rng).into();
        let incorrect_secret_key = Scalar::random(&mut rng).into();

        let keyholders_required = rng.gen_range(3..=10);
        let num_keyholders = rng.gen_range(keyholders_required..=keyholders_required + 5);

        let keyshares = generate_keyshares(
            &secret_key,
            NonZeroU32::new(keyholders_required).unwrap(),
            NonZeroU32::new(num_keyholders).unwrap(),
            &mut rng,
        )
        .unwrap();

        let truncated_keyshares: Vec<_> = keyshares
            .into_iter()
            .take(keyholders_required as usize - 2)
            .collect();

        commitments_from_secret_and_keyshares(
            &incorrect_secret_key,
            &truncated_keyshares,
            NonZeroU32::new(keyholders_required).unwrap(),
        )
        .expect_err(
            "should not be able to calculate commitments where insufficient keyshares were provided",
        );
    }

    #[test]
    fn cannot_generate_commitments_from_mixed_up_keyshares() {
        let mut rng = thread_rng();
        let secret_key = Scalar::random(&mut rng).into();
        let incorrect_secret_key = Scalar::random(&mut rng).into();

        let keyholders_required = rng.gen_range(3..=10);
        let num_keyholders = rng.gen_range(keyholders_required..=keyholders_required + 5);

        let mut keyshares = generate_keyshares(
            &secret_key,
            NonZeroU32::new(keyholders_required).unwrap(),
            NonZeroU32::new(num_keyholders).unwrap(),
            &mut rng,
        )
        .unwrap();

        keyshares.shuffle(&mut rng);

        commitments_from_secret_and_keyshares(
            &incorrect_secret_key,
            &keyshares,
            NonZeroU32::new(keyholders_required).unwrap(),
        )
        .expect_err(
            "should not be able to calculate commitments from keyshares which are not in order",
        );
    }

    #[test]
    fn can_serialize_and_deserialize_active_security_key() {
        let commitments = vec![
            Commitment::hash_from_bytes_for_tests_only(&[1]),
            Commitment::hash_from_bytes_for_tests_only(&[2]),
        ];
        let as_key = ActiveSecurityKey::from_commitments(commitments);

        let encoded_key = serde_json::to_string(&as_key).unwrap();
        let decoded_key = serde_json::from_str::<ActiveSecurityKey>(&encoded_key)
            .expect("couldn't deserialise active security key");

        assert_eq!(as_key, decoded_key);
    }
}
