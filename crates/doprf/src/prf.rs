// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use hex::FromHexError;
use rand::{rngs::OsRng, Rng};
#[cfg(any(feature = "centralized_keygen", test))]
use rand::{CryptoRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha3::Sha3_512;

use crate::active_security::{ActiveSecurityKey, RandomizedTarget};
#[cfg(any(feature = "centralized_keygen", test))]
use crate::lagrange::evaluate_lagrange_polynomial;
use crate::party::{KeyserverId, KeyserverIdSet};
use crate::tagged::{HashTag, TaggedHash};

/// The probability that a malicious party could evade active security is 2^(-SECURITY_PARAMETER).
/// Values of 4N+2 for N=0,1,... will maximise security vs speed.
/// A value of 18 entails a 2.5% performance reduction.
pub const SECURITY_PARAMETER: u32 = 18;

#[derive(Debug, Clone, Copy)]
pub struct Query(CompressedRistretto);

impl Query {
    #[cfg(feature = "centralized_keygen")]
    pub fn hash_from_string(seq: &str) -> Self {
        Self(RistrettoPoint::hash_from_bytes::<Sha3_512>(seq.as_bytes()).compress())
    }
}

/// Response from a keyholder: (H(x)^r)^{f(i)*c_i}
#[derive(Debug, Clone, Copy)]
pub struct HashPart(CompressedRistretto);

#[derive(Debug, Clone, Copy)]
pub struct CompletedHashValue(CompressedRistretto);

#[derive(Debug, Clone, Copy)]
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
}

#[derive(Debug, Clone)]
pub struct QueryState {
    required_keyholders: usize,
    blinding_factor: Scalar,
    verification_factor: Scalar,
    query: Query,
    responses: Vec<(KeyserverId, HashPart)>,
}

impl QueryState {
    pub fn new(bytes: &[u8], required_keyholders: usize) -> Self {
        let point = RistrettoPoint::hash_from_bytes::<Sha3_512>(bytes);

        Self::from_rp(point, required_keyholders, Scalar::ONE)
    }

    pub fn from_rp(
        point: RistrettoPoint,
        required_keyholders: usize,
        verification_factor: Scalar,
    ) -> Self {
        let mut rng = OsRng;
        let blinding_factor = Scalar::random(&mut rng);

        QueryState {
            required_keyholders,
            blinding_factor,
            verification_factor,
            query: Query::from_rp(point * blinding_factor),
            responses: vec![],
        }
    }

    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn incorporate_response(&mut self, i: KeyserverId, p: HashPart) {
        self.responses.reserve_exact(
            self.required_keyholders
                .saturating_sub(self.responses.len()),
        );
        self.responses.push((i, p));
    }

    /// Whether enough responses have been incorporated to reconstruct hash
    pub fn has_hash(&self) -> bool {
        self.responses.len() >= self.required_keyholders
    }

    /// Attempts to reconstruct the hash from incorporated responses.
    /// Returns `None` if not enough responses have been incorporated.
    fn calculate_hash_value(&self) -> Option<RistrettoPoint> {
        if self.has_hash() {
            let inverted_modification = self.blinding_factor.invert();
            let sum_hash_parts = self
                .responses
                .iter()
                .map(|(_, hash_part)| hash_part.to_rp())
                .sum::<RistrettoPoint>();
            Some(inverted_modification * sum_hash_parts)
        } else {
            None
        }
    }

    /// Attempts to reconstruct the hash from incorporated responses.
    /// Returns `None` if not enough responses have been incorporated.
    pub fn get_hash_value(&self) -> Option<CompletedHashValue> {
        self.calculate_hash_value().map(CompletedHashValue::from_rp)
    }

    /// The first value is the reconstructed hash, the second is used to verify that keyservers have
    /// correctly evaluated the DOPRF.
    pub fn get_hash_value_and_verification_value(
        &self,
    ) -> Option<(CompletedHashValue, RistrettoPoint)> {
        self.calculate_hash_value().map(|result| {
            let verifier = RistrettoPoint::vartime_double_scalar_mul_basepoint(
                &self.verification_factor,
                &result,
                &Scalar::ZERO,
            );
            (CompletedHashValue::from_rp(result), verifier)
        })
    }
}

#[derive(Debug, Clone)]
pub enum QueryError {
    WrongSizeResponse,
    MissingKeyserverResponse,
    ValidationFailed(Vec<KeyserverId>),
}

impl Error for QueryError {}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryError::WrongSizeResponse => {
                write!(f, "Query response has the wrong size")
            }
            QueryError::ValidationFailed(keyservers) => {
                write!(
                    f,
                    "Query response did not validate. Responsible keyservers: {:?}",
                    keyservers
                )
            }
            QueryError::MissingKeyserverResponse => {
                write!(f, "Missing keyserver response")
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct QueryStateSet {
    querystates: Vec<(Option<HashTag>, QueryState)>,
    randomized_target: RandomizedTarget,
}

impl QueryStateSet {
    pub fn from_iter(
        iter: impl IntoIterator<Item = (HashTag, impl AsRef<[u8]>)>,
        required_keyholders: usize,
        active_security_key: ActiveSecurityKey,
    ) -> Self {
        let randomized_target = active_security_key.randomized_target();

        let iter = iter.into_iter();
        let estimated_size = iter.size_hint().0 + 1;
        let mut querystates = Vec::with_capacity(estimated_size);
        let mut sum = RistrettoPoint::identity();

        let verification_factor_max = 2u32.pow(SECURITY_PARAMETER);
        let mut rng = OsRng;
        for (tag, b) in iter {
            let point = RistrettoPoint::hash_from_bytes::<Sha3_512>(b.as_ref());
            let verification_factor = Scalar::from(rng.gen_range(0u32..=verification_factor_max));
            // We need variable time scalar * point multiplication; this is the fastest option provided by curve25519-dalek
            sum += RistrettoPoint::vartime_double_scalar_mul_basepoint(
                &verification_factor,
                &point,
                &Scalar::ZERO,
            );
            let state = QueryState::from_rp(point, required_keyholders, verification_factor);
            querystates.push((Some(tag), state));
        }

        let checksum = randomized_target.get_checksum_point_for_validation(&sum);
        let verification_factor_0 = Scalar::from(rng.gen_range(0u32..=verification_factor_max));
        let x_0 = checksum * verification_factor_0.invert();
        let checksum_state = QueryState::from_rp(x_0, required_keyholders, verification_factor_0);

        querystates.push((None, checksum_state));

        Self {
            querystates,
            randomized_target,
        }
    }

    pub fn len(&self) -> usize {
        self.querystates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn queries(&self) -> impl Iterator<Item = &Query> + '_ {
        self.querystates.iter().map(|qs| qs.1.query())
    }

    pub fn incorporate_response(
        &mut self,
        id: KeyserverId,
        parts: &[HashPart],
    ) -> Result<(), QueryError> {
        if parts.len() != self.len() {
            return Err(QueryError::WrongSizeResponse);
        }

        for (i, &part) in parts.iter().enumerate() {
            self.querystates[i].1.incorporate_response(id, part);
        }

        Ok(())
    }

    pub fn all_have_hash(&self) -> bool {
        self.querystates.iter().all(|qs| qs.1.has_hash())
    }

    /// This function will also most likely block for a long time, `async` callers should `spawn_blocking`
    pub fn get_hash_values(&self) -> Result<Vec<TaggedHash>, QueryError> {
        if !self.all_have_hash() {
            return Err(QueryError::MissingKeyserverResponse);
        }
        let (mut hashes, verifiers): (Vec<TaggedHash>, Vec<RistrettoPoint>) = self
            .querystates
            .iter()
            .map(|(tag, qs)| {
                let (hash, verification) = qs
                    .get_hash_value_and_verification_value()
                    .expect("all_have_hash is true but get_hash_value is None!");
                let tag = (*tag).unwrap_or_default();
                (TaggedHash { tag, hash }, verification)
            })
            .unzip();

        if self.randomized_target.validate_responses(&verifiers) {
            hashes.pop();
            Ok(hashes)
        } else {
            let keyservers_responsible = self.find_keyservers_with_invalid_contribution();
            Err(QueryError::ValidationFailed(keyservers_responsible))
        }
    }

    fn find_keyservers_with_invalid_contribution(&self) -> Vec<KeyserverId> {
        let mut individual_sums: BTreeMap<KeyserverId, RistrettoPoint> = BTreeMap::new();
        for (_, qs) in &self.querystates {
            let modification = qs.blinding_factor.invert() * qs.verification_factor;
            for (id, hash) in &qs.responses {
                let sum = individual_sums
                    .entry(*id)
                    .or_insert(RistrettoPoint::identity());
                *sum += hash.to_rp() * modification;
            }
        }
        let keyservers = KeyserverIdSet::from_iter(individual_sums.keys().cloned());
        individual_sums
            .into_iter()
            .filter(|(id, sum)| {
                !self
                    .randomized_target
                    .is_keyserver_response_valid(&keyservers, id, sum)
            })
            .map(|(id, _)| id)
            .collect()
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

impl Query {
    fn to_rp(self) -> RistrettoPoint {
        self.0.decompress().unwrap() // already verified to be valid via try_from_buf
    }
}

impl HashPart {
    fn to_rp(self) -> RistrettoPoint {
        self.0.decompress().unwrap() // already verified to be valid via try_from_buf
    }
}

//Todo: why not in blanket impl?
impl CompletedHashValue {
    pub fn to_rp(self) -> RistrettoPoint {
        self.0.decompress().unwrap() // already verified to be valid via try_from_buf
    }
}

// In some sense we ought to be able to use blanket impls for these, and an
// `IsRistrettoPoint` trait. But in fact Rust doesn't know that a private
// trait can't have nonlocal impls, so it won't let us do things that way.
#[macro_export]
macro_rules! impls_for_ristretto_point {
    ($type_: ident) => {
        impl $type_ {
            pub fn from_rp(point: RistrettoPoint) -> Self {
                $type_(point.compress())
            }

            fn try_from_buf(bytes: &[u8; 32]) -> Result<Self, DecodeError> {
                let compressed_rp = CompressedRistretto::from_slice(bytes)
                    .map_err(|_| DecodeError::InvalidRistrettoPoint)?;
                if compressed_rp.decompress().is_some() {
                    Ok(Self(compressed_rp))
                } else {
                    Err(DecodeError::InvalidRistrettoPoint)
                }
            }

            fn display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(<[u8; 32]>::from(self)))
            }

            fn from_ristretto_str(s: &str) -> Result<Self, DecodeError> {
                let bytes = hex::decode(s)
                    .map_err(DecodeError::HexError)?
                    .try_into()
                    .map_err(|_| DecodeError::InvalidRistrettoPoint)?;
                if let Some(point) = CompressedRistretto(bytes).decompress() {
                    Ok(Self::from_rp(point))
                } else {
                    Err(DecodeError::InvalidRistrettoPoint)
                }
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0 .0
            }
        }
        impl FromStr for $type_ {
            type Err = DecodeError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_ristretto_str(s)
            }
        }
        impl fmt::Display for $type_ {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.display(f)
            }
        }
        impl From<&$type_> for [u8; 32] {
            fn from(t: &$type_) -> Self {
                t.0 .0
            }
        }
        impl From<$type_> for [u8; 32] {
            fn from(t: $type_) -> Self {
                (&t).into()
            }
        }
        impl TryFrom<&[u8; 32]> for $type_ {
            type Error = DecodeError;
            fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
                Self::try_from_buf(bytes)
            }
        }
        impl TryFrom<[u8; 32]> for $type_ {
            type Error = DecodeError;
            fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        impl Serialize for $type_ {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&format!("{}", &self))
            }
        }

        impl<'de> Deserialize<'de> for $type_ {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                FromStr::from_str(&s).map_err(de::Error::custom)
            }
        }

        impl $type_ {
            /// This method is marked as only for tests, because it's not needed for the main
            /// protocol, and there's no reason to be doing it. We only need it to generate
            /// arbitrary values during testing.
            pub fn hash_from_bytes_for_tests_only(bytes: &[u8]) -> $type_ {
                let rp = RistrettoPoint::hash_from_bytes::<Sha3_512>(bytes);
                $type_::from_rp(rp)
            }
        }
    };
}

impls_for_ristretto_point!(Query);
impls_for_ristretto_point!(HashPart);
impls_for_ristretto_point!(CompletedHashValue);

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use quickcheck::{quickcheck, Arbitrary, Gen};
    use rand::seq::SliceRandom;
    use rand::Rng;

    struct FakeCryptoRng<'a>(&'a mut Gen);

    impl RngCore for FakeCryptoRng<'_> {
        fn next_u32(&mut self) -> u32 {
            u32::arbitrary(self.0)
        }

        fn next_u64(&mut self) -> u64 {
            u64::arbitrary(self.0)
        }

        fn fill_bytes(&mut self, bytes: &mut [u8]) {
            for byte in bytes.iter_mut() {
                *byte = u8::arbitrary(self.0)
            }
        }

        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> std::result::Result<(), rand::Error> {
            self.fill_bytes(bytes);
            Ok(())
        }
    }

    impl<'a> CryptoRng for FakeCryptoRng<'a> {}

    #[derive(Clone, Debug)]
    struct Dna(String);

    impl Arbitrary for Dna {
        fn arbitrary(g: &mut Gen) -> Self {
            // Using Vec::arbitrary(g) until g.gen_range(0..g.size()) is public
            let len = 3 * Vec::<()>::arbitrary(g).len();
            let dna = (0..len)
                .filter_map(|_| g.choose(&['a', 'c', 'g', 't']))
                .collect();
            Self(dna)
        }
    }

    #[derive(Clone, Debug)]
    struct KeyShares {
        secret: KeyShare,
        shares: Vec<KeyShare>,
        chosen_keyservers: Vec<usize>,
    }

    impl Arbitrary for KeyShares {
        fn arbitrary(g: &mut Gen) -> Self {
            Self::random(&mut FakeCryptoRng(g))
        }
    }

    impl KeyShares {
        fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
            let secret = Scalar::random(rng).into();
            let num_required_keyshares = rng.gen_range(2..6);
            let num_additional_keys = rng.gen_range(0..6);
            let total_keys = NonZeroU32::new(num_required_keyshares + num_additional_keys).unwrap();
            let num_required_keyshares = NonZeroU32::new(num_required_keyshares).unwrap();

            let shares =
                generate_keyshares(&secret, num_required_keyshares, total_keys, rng).unwrap();
            let chosen_keyservers = rand::seq::index::sample(
                rng,
                total_keys.get() as usize,
                num_required_keyshares.get() as usize,
            )
            .into_vec();

            Self {
                secret,
                shares,
                chosen_keyservers,
            }
        }

        fn chosen_keyservers_and_shares(
            &self,
        ) -> impl ExactSizeIterator<Item = (KeyserverId, &KeyShare)> {
            self.chosen_keyservers.iter().map(|&ks_i| {
                (
                    KeyserverId::try_from(ks_i as u32 + 1).unwrap(),
                    &self.shares[ks_i],
                )
            })
        }

        fn corrupt_random_subset_of_chosen_keyservers(
            &mut self,
        ) -> Result<Vec<KeyserverId>, &'static str> {
            let mut rng = rand::thread_rng();
            let subset_size = rng.gen_range(1..self.chosen_keyservers.len());
            let corrupted_ks: Vec<usize> = self
                .chosen_keyservers
                .choose_multiple(&mut rng, subset_size)
                .cloned()
                .collect();
            self.corrupt_keyservers_by_index(&corrupted_ks)?;
            let corrupted_ids = corrupted_ks
                .into_iter()
                .map(|ks_i| KeyserverId::try_from(ks_i as u32 + 1).unwrap())
                .sorted()
                .collect();
            Ok(corrupted_ids)
        }

        fn corrupt_keyservers_by_index(
            &mut self,
            ks_to_corrupt: &[usize],
        ) -> Result<(), &'static str> {
            for &ks_i in ks_to_corrupt {
                if let Some(ks) = self.shares.get_mut(ks_i) {
                    *ks = Scalar::random(&mut OsRng).into();
                } else {
                    return Err("Keyserver index out of bounds.");
                }
            }
            Ok(())
        }
    }

    fn hash_via_keyshares(
        keyshares: &KeyShares,
        windows: impl IntoIterator<Item = impl AsRef<[u8]>>,
        target: ActiveSecurityKey,
    ) -> Result<Vec<CompletedHashValue>, QueryError> {
        let mut querystates = QueryStateSet::from_iter(
            windows
                .into_iter()
                .enumerate()
                .map(|(i, x)| (HashTag::new(i == 0, 0, i), x)),
            keyshares.chosen_keyservers.len(),
            target,
        );
        let keyserver_ids: KeyserverIdSet = keyshares
            .chosen_keyservers
            .iter()
            .map(|index| KeyserverId::try_from(*index as u32 + 1).unwrap())
            .collect();
        for (ks_id, key) in keyshares.chosen_keyservers_and_shares() {
            let coeff = keyserver_ids.langrange_coefficient_for_id(&ks_id);
            let hashparts: Vec<_> = querystates
                .queries()
                .map(|q| key.apply_query_and_lagrange_coefficient(*q, &coeff))
                .collect();
            querystates.incorporate_response(ks_id, &hashparts).unwrap();
        }
        querystates
            .get_hash_values()
            .map(|v| v.iter().map(|x| x.hash).collect())
    }

    // Finds a message for which distributed key hashing doesn't match single-key hashing
    fn find_message_with_mismatching_hashes<'a>(
        keys: KeyShares,
        messages: impl IntoIterator<Item = &'a [u8]> + Clone,
        target: ActiveSecurityKey,
    ) -> Option<&'a [u8]> {
        let distributed_hashes = hash_via_keyshares(&keys, messages.clone(), target).unwrap();
        for (message, distributed_hash) in messages.into_iter().zip(distributed_hashes) {
            let query = Query::hash_from_bytes_for_tests_only(message);
            let single_key_hash = keys.secret.apply(query);
            if <[u8; 32]>::from(distributed_hash) != <[u8; 32]>::from(single_key_hash) {
                return Some(message);
            }
        }
        None
    }

    // Quick sanity check... Run with -- --ignored to do more comprehensive tests
    #[test]
    fn test_batched_distributed_encryption_matches_single_key_encryption() {
        let keys = KeyShares::random(&mut OsRng);
        let keyholders_required = NonZeroU32::new(keys.chosen_keyservers.len() as u32).unwrap();

        let target = ActiveSecurityKey::from_secret_and_keyshares(
            &keys.secret,
            &keys.shares,
            keyholders_required,
        )
        .unwrap();
        let messages = [
            "foobar",
            "The five boxing wizards jump quickly.",
            "",
            "acgtacgtacgt",
            "xyzzy",
        ]
        .map(AsRef::<[u8]>::as_ref);
        assert_eq!(
            find_message_with_mismatching_hashes(keys, messages, target),
            None
        );
    }

    #[test]
    fn corrupted_keyservers_cause_query_error_and_are_correctly_identified() {
        let mut keys = KeyShares::random(&mut OsRng);
        let keyholders_required = NonZeroU32::new(keys.chosen_keyservers.len() as u32).unwrap();

        let target = ActiveSecurityKey::from_secret_and_keyshares(
            &keys.secret,
            &keys.shares,
            keyholders_required,
        )
        .unwrap();

        let corrupted_ks = keys.corrupt_random_subset_of_chosen_keyservers().unwrap();

        let messages = [
            "foobar",
            "The five boxing wizards jump quickly.",
            "",
            "acgtacgtacgt",
            "xyzzy",
        ]
        .map(AsRef::<[u8]>::as_ref);

        let result = hash_via_keyshares(&keys, messages, target);

        assert!(
            matches!(
            result, Err(QueryError::ValidationFailed(ref responsible_ks)) if responsible_ks == &corrupted_ks),
            "Should have found corrupted ks {:?}, found {:?}",
            corrupted_ks,
            result
        );
    }

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

    quickcheck! {

        #[ignore]
        fn distributed_hashing_matches_single_key_hashing(keys: KeyShares, dna: Dna) -> bool {
            let dna: &[u8] = dna.0.as_ref();
            let windows = dna.windows(50);
            let keyholders_required = NonZeroU32::new(keys.chosen_keyservers.len() as u32).unwrap();

        let target =
            ActiveSecurityKey::from_secret_and_keyshares(&keys.secret, &keys.shares, keyholders_required).unwrap();
            find_message_with_mismatching_hashes(keys, windows, target).is_none()
        }

    }
}
