// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contains [`Blinder`], used for (un)blinding [`RistrettoPoint`]s.

use std::borrow::{Borrow, BorrowMut};

use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};

/// Randomized factors for (un)blinding [`RistrettoPoint`]s.
///
/// It's important that clients avoid leaking queries to keyservers.
/// To avoid that, we blind (i.e. multiply by a random [`Scalar`]) queries before sending
/// them to keyservers and unblind (i.e. divide by the same random [`Scalar`]) the responses.
/// This works because keyservers just multiply the given [`RistrettoPoint`]s by [`Scalar`]\(s)
/// representing the keyserver's keyshare (and possibly a Lagrange coefficient), and
/// [`Scalar`]-related multiplications are associative and commutative. In other words,
/// if 𝑋 is a query (a [`RistrettoPoint`]), 𝑟 is a blinding factor (a [`Scalar`])
/// and 𝑘 is a keyshare (a [`Scalar`]), then the steps we take are:
/// * Obtain 𝑋 from e.g. hashing a window.
/// * Client blinds and sends it to the keyserver: 𝑟𝑋
/// * Keyserver applies its keyshare and returns it: 𝑘𝑟𝑋
/// * Client unblinds it: 𝑘𝑟𝑋/𝑟, which simplifies to 𝑘𝑋.
///
/// Thus, the client learns 𝑘𝑋 (the result of applying the keyshare to 𝑋), but the keyserver has
/// no clue what 𝑋 was because it only saw 𝑟𝑋 which has no relationship to 𝑋 because
/// 𝑟 is completely random.
#[derive(Clone, Default, Debug)]
pub struct Blinder {
    // Ok, the above docs are (slight) lies; we store unblinding factors because we may have
    // to unblind multiple times (if verification fails), but we only need to blind once,
    // so it's potentially less computation to invert the random factor when blinding.
    unblinding_factors: Vec<Scalar>,
}

impl Blinder {
    /// Create [`Blinder`] holding `len` blinding factors randomly created from `rng`.
    pub fn new(mut rng: impl CryptoRng + RngCore, len: usize) -> Self {
        let unblinding_factors = (0..len).map(|_| Scalar::random(&mut rng)).collect();
        Self { unblinding_factors }
    }

    /// Create [`Blinder`] and use it to blind `queries`.
    ///
    /// This blinds `queries`, mutating them in place using random factors created from
    /// `rng`, then returns a [`Blinder`] capable of unblinding them.
    pub fn from_blinding_in_place(
        mut rng: impl CryptoRng + RngCore,
        queries: impl IntoIterator<Item: BorrowMut<RistrettoPoint>>,
    ) -> Self {
        let unblinding_factors = queries
            .into_iter()
            .map(|mut rp| {
                let unblinding_factor = Scalar::random(&mut rng);
                *rp.borrow_mut() *= unblinding_factor.invert();
                unblinding_factor
            })
            .collect();
        Self { unblinding_factors }
    }

    /// Iterator adapter returning blinded `queries`.
    ///
    /// # Panics
    ///
    /// This will panic if the number of supplied `queries` differs from the number of
    /// blinding factors and the iterator is exhausted.
    pub fn blinded<Q>(&self, queries: Q) -> impl Iterator<Item = RistrettoPoint> + use<'_, Q>
    where
        Q: IntoIterator<Item: Borrow<RistrettoPoint>>,
    {
        itertools::zip_eq(&self.unblinding_factors, queries)
            .map(|(unblinding_factor, rp)| unblinding_factor.invert() * rp.borrow())
    }

    /// Iterator adapter returning unblinded versions of `blinded`.
    ///
    /// # Panics
    ///
    /// This will panic if the number of supplied `blinded` differs from the number of
    /// blinding factors and the iterator is exhausted.
    pub fn unblinded<B>(&self, blinded: B) -> impl Iterator<Item = RistrettoPoint> + use<'_, B>
    where
        B: IntoIterator<Item: Borrow<RistrettoPoint>>,
    {
        let blinded = blinded.into_iter().map(Ok::<_, std::convert::Infallible>);
        self.try_unblinded(blinded).map(|Ok(rp)| rp)
    }

    /// Fallible iterator adapter returning unblinded versions of `blinded`.
    ///
    /// # Panics
    ///
    /// This will panic if the number of supplied `blinded` differs from the number of
    /// blinding factors and the iterator is exhausted.
    pub fn try_unblinded<B, R, E>(
        &self,
        blinded: B,
    ) -> impl Iterator<Item = Result<RistrettoPoint, E>> + use<'_, B, R, E>
    where
        B: IntoIterator<Item = Result<R, E>>,
        R: Borrow<RistrettoPoint>,
    {
        itertools::zip_eq(&self.unblinding_factors, blinded)
            .map(|(unblinding_factor, rp)| rp.map(|rp| unblinding_factor * rp.borrow()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::traits::Identity;
    use quickcheck::quickcheck;
    use rand::rngs::OsRng;

    use crate::testutil::TestRng;

    fn none_equal<T: PartialEq>(ls: &[T], rs: &[T]) -> bool {
        ls.iter().zip(rs).all(|(l, r)| l != r)
    }

    fn assert_none_equal<T: PartialEq + std::fmt::Debug>(ls: &[T], rs: &[T]) {
        for (i, (l, r)) in ls.iter().zip(rs).enumerate() {
            assert_ne!(l, r, "element {i} of lists shouldn't be equal")
        }
    }

    #[test]
    fn smoke_test_new_and_blinded() {
        let queries: Vec<_> = (0..5).map(|_| RistrettoPoint::random(&mut OsRng)).collect();
        let blinder = Blinder::new(&mut OsRng, queries.len());
        let blinded: Vec<_> = blinder.blinded(&queries).collect();
        let unblinded: Vec<_> = blinder.unblinded(&blinded).collect();
        assert_none_equal(&queries, &blinded);
        assert_eq!(queries, unblinded);
    }

    #[test]
    fn smoke_test_from_blinding_in_place() {
        let queries: Vec<_> = (0..5).map(|_| RistrettoPoint::random(&mut OsRng)).collect();
        let mut blinded = queries.clone();
        let blinder = Blinder::from_blinding_in_place(&mut OsRng, &mut blinded);
        let unblinded: Vec<_> = blinder.unblinded(&blinded).collect();
        assert_none_equal(&queries, &blinded);
        assert_eq!(queries, unblinded);
    }

    #[test]
    fn smoke_test_try_unblind() {
        let queries: Vec<_> = (0..5).map(|_| RistrettoPoint::random(&mut OsRng)).collect();
        let blinder = Blinder::new(&mut OsRng, queries.len());
        let mut blinded: Vec<_> = blinder.blinded(&queries).map(Ok).collect();
        blinded[2] = Err("oh no");
        let mut expected: Vec<_> = queries.iter().copied().map(Ok).collect();
        expected[2] = Err("oh no");
        let unblinded: Vec<_> = blinder.try_unblinded(blinded).collect();
        assert_eq!(unblinded, expected);
    }

    #[test]
    #[should_panic]
    fn blinding_rejects_too_many_ristrettos() {
        let blinder = Blinder::new(&mut OsRng, 3);
        let queries = vec![RistrettoPoint::identity(); 4];
        blinder.blinded(queries).for_each(|_| {});
    }

    #[test]
    #[should_panic]
    fn blinding_rejects_too_few_ristrettos() {
        let blinder = Blinder::new(&mut OsRng, 4);
        let queries = vec![RistrettoPoint::identity(); 3];
        blinder.blinded(queries).for_each(|_| {});
    }

    #[test]
    #[should_panic]
    fn unblinding_rejects_too_many_ristrettos() {
        let blinder = Blinder::new(&mut OsRng, 3);
        let queries = vec![RistrettoPoint::identity(); 4];
        blinder.unblinded(queries).for_each(|_| {});
    }

    #[test]
    #[should_panic]
    fn unblinding_rejects_too_few_ristrettos() {
        let blinder = Blinder::new(&mut OsRng, 4);
        let queries = vec![RistrettoPoint::identity(); 3];
        blinder.unblinded(queries).for_each(|_| {});
    }

    quickcheck! {

        #[ignore]
        fn quickcheck_new_and_blinded(rng: TestRng, queries: Vec<()>) -> bool {
            let mut rng = rng;
            let queries: Vec<_> = queries
                .iter()
                .map(|_| RistrettoPoint::random(&mut rng))
                .collect();
            let blinder = Blinder::new(&mut rng, queries.len());
            let blinded: Vec<_> = blinder.blinded(&queries).collect();
            let unblinded: Vec<_> = blinder.unblinded(&blinded).collect();
            none_equal(&queries, &blinded) && queries == unblinded
        }

        #[ignore]
        fn quickcheck_from_blinding_in_place(rng: TestRng, queries: Vec<()>) -> bool {
            let mut rng = rng;
            let queries: Vec<_> = queries
                .iter()
                .map(|_| RistrettoPoint::random(&mut rng))
                .collect();
            let mut blinded = queries.clone();
            let blinder = Blinder::from_blinding_in_place(&mut rng, &mut blinded);
            let unblinded: Vec<_> = blinder.unblinded(&blinded).collect();
            none_equal(&queries, &blinded) && queries == unblinded
        }

    }
}
