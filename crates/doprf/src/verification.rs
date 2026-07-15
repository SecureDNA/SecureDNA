// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contains [`Verifier`], used for active security.

use std::borrow::Borrow;

use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, Rng, RngCore};

/// Implements active security (verifying that keyservers are applying their keyshare correctly).
///
/// If a misconfigured (or malicious) keyserver were to apply their keyshare incorrectly, it would
/// cause hazards to be silently missed. We really, *really* want to avoid that, so we need a way
/// of verifing that each keyserver is working as advertised...
///
/// The keyservers hold keyshares 𝑘₁, 𝑘₂, … which together can be used to calculate the database
/// key 𝑘₀. We have query points 𝑋₁, 𝑋₂, …, 𝑋ₙ and we want to verify that e.g. keyserver 2 returns
/// 𝑘₂𝑋₁, 𝑘₂𝑋₂, …, 𝑘₂𝑋ₙ, without the keyserver being required to reveal 𝑘₂.
///
/// For each key(share) 𝑘ᵢ, we define its 'commitment' 𝐶ᵢ as being the result of multiplying
/// the key(share) 𝑘ᵢ by the [ristretto basepoint] 𝐵. For instance, the commitment 𝐶₀ to the
/// database key is 𝑘₀𝐵 and the commitment 𝐶₂ to the second keyserver's keyhsare is 𝑘₂𝐵.
/// Importantly, each commitment 𝐶ᵢ does not reveal the original key(share) 𝑘ᵢ. We refer to
/// the set of all commitments (𝐶₀, 𝐶₁, 𝐶₂, …) as the 'active security key'.
///
/// Once other code has determined the active security key, we can use its commitments to verify
/// that the database key 𝑘₀ (or any keyshare 𝑘ᵢ) has been applied correctly to our 𝑋₁, 𝑋₂, …, 𝑋ₙ
/// points. As long as 𝑋₁ + 𝑋₂ + … + 𝑋ₙ = 𝐵, we know 𝑐𝑋₁ + 𝑐𝑋₂ + … + 𝑐𝑋ₙ = 𝑐𝐵 for any 𝑐. Therefore
/// by adding an extra 'balancer' element 𝑋ₙ₊₁ to our points so that their sum is 𝐵, we give
/// ourselves the ability to check that the returned values sum to 𝐶₀ (which we know is equal
/// to 𝑘₀𝐵).
///
/// However, if the keyservers know the value of this 'target' (the value we are expecting the
/// elements to sum to) they can manipulate their response so that the sum of the values returned
/// equals 𝐶₀ without each individual element of the response having been correctly multiplied by
/// 𝑘₀. To avoid this we are required to perform two extra steps.
///
/// 1. We randomly modify the 'target' using the randomly generated value 𝑠, so that the keyservers
///    don't know what value their response should sum to.
/// 2. We multiply our 𝑋₁, 𝑋₂, …, 𝑋ₙ points by randomly generated 'verification factors'
///    𝑑₁, 𝑑₂, …, 𝑑ₙ and use these in our calculation of the balancer element. If we do not take
///    this second step there is a greater than 50% chance that a malicious keyserver could create
///    a response in which at least one of the query elements had not had the key applied correctly,
///    yet where the element's sum was equal to the random target. Verification factors make that
///    much less likely. (see [caveat](#caveat) for details)
///
/// We randomly generate our verification factors and target modifier 𝑠, and calculate our balancer
/// element 𝑋ₙ₊₁ such that 𝑑₁𝑋₁ + 𝑑₂𝑋₂ + … + 𝑑ₙ𝑋ₙ + 𝑑ₙ₊₁𝑋ₙ₊₁ = 𝑠𝐵. Note that the values we send to
/// the keyservers do not include the verification factors; they are solely for use in verifying
/// the keyserver responses.
///
/// It's also important to note that this works not just for 𝑘₀ but for any keyshare, or *any*
/// multiplier for that matter, so long as you have the appropriate commitment. This means we can
/// verify any multiple of a keyshare, which ends up being important because recombining hash parts
/// into completed hashes involves multiplying them by Lagrange coefficients and we speed up the
/// client by offloading that work onto keyservers, so instead of checking that each keyserver just
/// multiplies by its keyshare, we need to check that it multiplies by both its keyshare and
/// Lagrange coefficient.
///
/// Finally, one last optimization is that a balancer and verification factors can be reused to
/// check several different key(share)s.
///
/// # Maths
///
/// Just to summarize the above: Lets say we have query points 𝑋₁, 𝑋₂, …, 𝑋ₙ. We randomly
/// choose a target modifier 𝑠 and verification factors 𝑑₁, 𝑑₂, …, 𝑑ₙ, 𝑑ₙ₊₁ (note the extra one
/// for the balancer). We append balancer 𝑋ₙ₊₁, which we calculate via
/// (𝑠𝐵 − 𝑑₁𝑋₁ − 𝑑₂𝑋₂ − … − 𝑑ₙ𝑋ₙ) / 𝑑ₙ₊₁. We send 𝑋₁, 𝑋₂, …, 𝑋ₙ, 𝑋ₙ₊₁ off to a keyserver.
///
/// Assuming the keyserver has a keyshare 𝑘, it should return the points 𝑘𝑋₁, 𝑘𝑋₂, …, 𝑘𝑋ₙ, 𝑘𝑋ₙ₊₁.
///
/// To check the validity of the response, we multiply each point by its corresponding verification
/// factor and sum them:
/// * 𝑑₁(𝑘𝑋₁) + 𝑑₂(𝑘𝑋₂) + … + 𝑑ₙ(𝑘𝑋ₙ) + 𝑑ₙ₊₁(𝑘𝑋ₙ₊₁)
///
/// This should simplify as follows:
/// * 𝑑₁𝑘𝑋₁ + 𝑑₂𝑘𝑋₂ + … + 𝑑ₙ𝑘𝑋ₙ + 𝑑ₙ₊₁𝑘𝑋ₙ₊₁
/// * 𝑘(𝑑₁𝑋₁ + 𝑑₂𝑋₂ + … + 𝑑ₙ𝑋ₙ + 𝑑ₙ₊₁𝑋ₙ₊₁)
/// * 𝑘(𝑑₁𝑋₁ + 𝑑₂𝑋₂ + … + 𝑑ₙ𝑋ₙ + 𝑑ₙ₊₁ (𝑠𝐵 − 𝑑₁𝑋₁ − 𝑑₂𝑋₂ − … − 𝑑ₙ𝑋ₙ) / 𝑑ₙ₊₁)
/// * 𝑘(𝑑₁𝑋₁ + 𝑑₂𝑋₂ + … + 𝑑ₙ𝑋ₙ + (𝑠𝐵 − 𝑑₁𝑋₁ − 𝑑₂𝑋₂ − … − 𝑑ₙ𝑋ₙ))
/// * 𝑘(𝑠𝐵)
/// * 𝑠𝑘𝐵
///
/// ...which is the keyserver's commitment multiplied by 𝑠. If the keyserver is also multiplying
/// by a Lagrange coefficient, the math works out the same, except instead the result is the
/// commitment multiplied by 𝑠 and the Lagrange coefficient.
///
/// # Caveat
///
/// To avoid a severe performance reduction from applying verification factors, we use
/// variable-time multiplication and only pick verification factors up to 2ᴷ, where κ is the
/// `security_strength` passed to [`Verifier::balancer_and_verifier`]. This should only allow
/// a malicious keyserver to have a 2⁻ᴷ chance of misbehaving undetected. However, to avoid
/// side-channel leaks from the variable-time multiplication, batches of queries must be padded
/// with random [`RistrettoPoint`]s if they contain fewer than 100 or so.
///
/// # Example
///
/// ```
/// use curve25519_dalek::{RistrettoPoint, Scalar};
/// use doprf::Verifier;
/// use rand::rngs::OsRng;
///
/// // In real code, these would be generated from hashing windows.
/// let mut queries: Vec<_> = (0..10).map(|_| RistrettoPoint::random(&mut OsRng)).collect();
/// // Setup a verifier and add the balancer... the security_strength tunes the verification
/// // quality; high values are better but more computationally expensive.
/// let security_strength = 18;
/// let (balancer, verifier) =
///     Verifier::balancer_and_verifier(&mut OsRng, security_strength, &queries);
/// queries.push(balancer);
///
/// // Keyservers transform RistrettoPoints by multiplying them by a particular key.
/// let key = Scalar::random(&mut OsRng);
/// // In real code, the commitment would likely be discovered during server selection.
/// let commitment = RistrettoPoint::mul_base(&key);
/// let mut multiplied: Vec<_> = queries.iter().map(|query| key * query).collect();
///
/// // We correctly multiplied everything so they match the commitment.
/// assert!(verifier.verify(&multiplied, &commitment).is_ok());
///
/// // However, if the keyserver had deliberately messed up one of the transformed queries...
/// multiplied[3] = RistrettoPoint::random(&mut OsRng);
/// // ...the results no longer match the commitment.
/// assert!(verifier.verify(&multiplied, &commitment).is_err());
/// ```
///
/// [ristretto basepoint]: curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
#[derive(Clone, Debug, Default)]
pub struct Verifier {
    verification_factors: Vec<Scalar>,
    target_modifier: Scalar,
}

/// Indicates verification of (multiplied) [`RistrettoPoint`]s failed.
///
/// See [`Verifier::verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerificationFailure;

impl Verifier {
    /// Generate balancer and return [`Verifier`].
    ///
    /// Given a set of `queries`, this will return a balancer and a [`Verifier`].
    /// The balancer must be appended to `queries` before sending them to a keyserver.
    /// Afterwards, the keyserver's response can be fed into [`Verifier::verify`] to ensure
    /// it correctly applied its keyshare to each query.
    pub fn balancer_and_verifier(
        mut rng: impl CryptoRng + RngCore,
        security_strength: u8,
        queries: impl IntoIterator<Item: Borrow<RistrettoPoint>, IntoIter: ExactSizeIterator>,
    ) -> (RistrettoPoint, Self) {
        let queries = queries.into_iter();
        let num_verification_factors = queries
            .len()
            .checked_add(1) // for balancer
            .expect("Too many verification factors to fit in memory.");
        let verification_factor_max = 2u32
            .checked_pow(security_strength as u32)
            .expect("security_strength cannot be more than 31");
        let verification_factors: Vec<_> = (0..num_verification_factors)
            .map(|_| Scalar::from(rng.gen_range(1u32..=verification_factor_max)))
            .collect();

        let target_modifier = Scalar::random(&mut rng);

        let (balancer_factor, hash_factors) = verification_factors
            .split_last()
            .expect("impossible because there's always a balancer verification factor");
        let balancer = (RistrettoPoint::mul_base(&target_modifier)
            - RistrettoPoint::vartime_multiscalar_mul(hash_factors, queries))
            * balancer_factor.invert();

        let this = Self {
            verification_factors,
            target_modifier,
        };
        (balancer, this)
    }

    /// Verify given `candidates` against `commitment`.
    ///
    /// Returns without error if `candidates` are 𝑘𝑋₁, 𝑘𝑋₂, …, 𝑘𝑋ₙ₊₁ and `commitment` is 𝑘𝐵,
    /// where:
    /// * 𝑘 is any [`Scalar`].
    /// * 𝑋₁, 𝑋₂, …, 𝑋ₙ are the `queries` passed to [`Verifier::balancer_and_verifier`].
    /// * 𝑋ₙ₊₁ is the balancer returned by [`Verifier::balancer_and_verifier`].
    /// * 𝐵 is the [ristretto basepoint].
    ///
    /// Otherwise, returns a [`VerificationFailure`].
    ///
    /// See the docs for [`Verifier`] for an overview and example code.
    ///
    /// [ristretto basepoint]: curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
    pub fn verify(
        &self,
        candidates: impl IntoIterator<Item: Borrow<RistrettoPoint>>,
        commitment: &RistrettoPoint,
    ) -> Result<(), VerificationFailure> {
        let sum = RistrettoPoint::vartime_multiscalar_mul(&self.verification_factors, candidates);
        if sum == self.target_modifier * commitment {
            Ok(())
        } else {
            Err(VerificationFailure)
        }
    }

    /// Return the number of `candidates` this [`Verifier`] expects to be passed to
    // [`verify`](Self::verify).
    pub fn expected_elements(&self) -> usize {
        self.verification_factors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck::{TestResult, quickcheck};
    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;

    use crate::testutil::TestRng;

    #[test]
    fn verifier_accepts_correctly_multiplied_ristrettos() {
        let mut rng = OsRng;
        let security_strength = 18;
        let mut queries: Vec<_> = (0..5).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let (balancer, verifier) =
            Verifier::balancer_and_verifier(&mut rng, security_strength, &queries);
        queries.push(balancer);

        let key = Scalar::random(&mut rng);
        let commitment = RistrettoPoint::mul_base(&key);
        let multiplied: Vec<_> = queries.iter().map(|q| key * q).collect();

        verifier.verify(&multiplied, &commitment).unwrap();
    }

    #[test]
    fn verifier_rejects_incorrectly_multiplied_ristrettos() {
        let mut rng = OsRng;
        let security_strength = 18;
        let mut queries: Vec<_> = (0..5).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let (balancer, verifier) =
            Verifier::balancer_and_verifier(&mut rng, security_strength, &queries);
        queries.push(balancer);

        let key = Scalar::random(&mut rng);
        let commitment = RistrettoPoint::mul_base(&key);
        let mut multiplied: Vec<_> = queries.iter().map(|q| key * q).collect();
        if let Some(r) = multiplied.choose_mut(&mut rng) {
            *r = RistrettoPoint::random(&mut rng);
        }

        verifier.verify(&multiplied, &commitment).unwrap_err();
    }

    #[test]
    fn verifier_has_correct_number_of_expected_elements() {
        let mut rng = OsRng;
        let security_strength = 18;
        let queries: Vec<_> = (0..5).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let (_balancer, verifier) =
            Verifier::balancer_and_verifier(&mut rng, security_strength, &queries);
        assert_eq!(verifier.expected_elements(), 6);
    }

    quickcheck! {

        #[ignore]
        fn quickcheck_verifier_accepts_correctly_multiplied_ristrettos(
            rng: TestRng,
            queries: Vec<()>
        ) -> TestResult {
            let mut rng = rng;
            if queries.len() > 1000 {
                return TestResult::discard();
            }
            let mut queries: Vec<_> = queries
                .iter()
                .map(|_| RistrettoPoint::random(&mut rng))
                .collect();

            let security_strength = rng.gen_range(0..32);
            let (balancer, verifier) =
                Verifier::balancer_and_verifier(&mut rng, security_strength, &queries);
            queries.push(balancer);

            let key = Scalar::random(&mut rng);
            let commitment = RistrettoPoint::mul_base(&key);
            let multiplied: Vec<_> = queries.iter().map(|q| key * q).collect();

            TestResult::from_bool(verifier.verify(&multiplied, &commitment).is_ok())
        }

        #[ignore]
        fn quickcheck_verifier_rejects_incorrectly_multiplied_ristrettos(
            rng: TestRng,
            queries: Vec<()>
        ) -> TestResult {
            let mut rng = rng;
            if queries.len() > 1000 {
                return TestResult::discard();
            }
            let mut queries: Vec<_> = queries
                .iter()
                .map(|_| RistrettoPoint::random(&mut rng))
                .collect();

            let security_strength = rng.gen_range(0..32);
            let (balancer, verifier) =
                Verifier::balancer_and_verifier(&mut rng, security_strength, &queries);
            queries.push(balancer);

            let key = Scalar::random(&mut rng);
            let commitment = RistrettoPoint::mul_base(&key);

            let mut multiplied: Vec<_> = queries.iter().map(|q| key * q).collect();
            if let Some(r) = multiplied.choose_mut(&mut rng) {
                *r = RistrettoPoint::random(&mut rng);
            }

            TestResult::from_bool(verifier.verify(&multiplied, &commitment).is_err())
        }
    }
}
