// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::num::NonZeroU32;
use std::ops::Range;

use curve25519_dalek::Scalar;
use quickcheck::{Arbitrary, Gen};
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use crate::active_security::ActiveSecurityKey;
use crate::party::{KeyserverId, KeyserverIdSet};
use crate::prf::{CompressedHashPart, CompressedQuery, KeyShare, generate_keyshares};

#[derive(Clone)]
pub(crate) struct TestRng {
    seed: <StdRng as SeedableRng>::Seed,
    rng: StdRng,
}

impl std::fmt::Debug for TestRng {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("TestRng")
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

impl Arbitrary for TestRng {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut seed = <Self as SeedableRng>::Seed::default();
        for byte in &mut seed {
            *byte = Arbitrary::arbitrary(g);
        }
        Self::from_seed(seed)
    }
}

impl SeedableRng for TestRng {
    type Seed = <StdRng as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            seed,
            rng: StdRng::from_seed(seed),
        }
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.rng.fill_bytes(bytes)
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.rng.try_fill_bytes(bytes)
    }
}

// This is a thin wrapper around `StdRng` which is `CryptoRng`.
impl CryptoRng for TestRng {}

#[derive(Clone, Debug)]
pub struct KeyShares {
    pub secret: KeyShare,
    pub shares: Vec<KeyShare>,
    pub active_security_key: ActiveSecurityKey,
}

impl Arbitrary for KeyShares {
    fn arbitrary(g: &mut Gen) -> Self {
        let rng = &mut TestRng::arbitrary(g);
        let num_required_keyshares = 2..6;
        let num_additional_keys = 0..6;
        Self::random(rng, num_required_keyshares, num_additional_keys)
    }
}

impl KeyShares {
    pub fn random(
        rng: &mut (impl RngCore + CryptoRng),
        num_required_keyshares: Range<u32>,
        num_additional_keys: Range<u32>,
    ) -> Self {
        assert!(num_required_keyshares.start > 0); // don't want failures randomized
        let num_required_keyshares = rng.gen_range(num_required_keyshares);
        let num_additional_keys = rng.gen_range(num_additional_keys);
        let total_keys = NonZeroU32::new(num_required_keyshares + num_additional_keys).unwrap();
        let num_required_keyshares = NonZeroU32::new(num_required_keyshares).unwrap();
        let secret = Scalar::random(rng).into();
        let shares = generate_keyshares(&secret, num_required_keyshares, total_keys, rng).unwrap();
        let active_security_key =
            ActiveSecurityKey::from_secret_and_keyshares(&secret, &shares, num_required_keyshares)
                .unwrap();
        Self {
            secret,
            shares,
            active_security_key,
        }
    }

    pub fn supported_quorum(&self) -> usize {
        self.active_security_key.supported_quorum()
    }

    pub fn random_quorum_set(&self, rng: &mut (impl RngCore + CryptoRng)) -> KeyserverIdSet {
        rand::seq::index::sample(rng, self.shares.len(), self.supported_quorum())
            .into_iter()
            .map(|i| KeyserverId::try_from((i + 1) as u32).unwrap())
            .collect()
    }

    pub fn share(&self, keyserver_id: KeyserverId) -> &KeyShare {
        &self.shares[keyserver_id.as_u32() as usize - 1]
    }

    pub fn share_mut(&mut self, keyserver_id: KeyserverId) -> &mut KeyShare {
        &mut self.shares[keyserver_id.as_u32() as usize - 1]
    }

    pub fn apply_keyshares(
        &self,
        keyserver_ids: &KeyserverIdSet,
        queries: impl IntoIterator<IntoIter: Clone, Item = CompressedQuery>,
    ) -> Vec<(KeyserverId, Vec<CompressedHashPart>)> {
        let queries = queries.into_iter();
        keyserver_ids
            .iter()
            .map(|ks_id| {
                let response = self.apply_keyshare(ks_id, keyserver_ids, queries.clone());
                (ks_id, response)
            })
            .collect()
    }

    pub fn apply_keyshare(
        &self,
        keyserver_id: KeyserverId,
        keyserver_ids: &KeyserverIdSet,
        queries: impl IntoIterator<Item = CompressedQuery>,
    ) -> Vec<CompressedHashPart> {
        let share = self.share(keyserver_id);
        let coeff = keyserver_ids.langrange_coefficient_for_id(&keyserver_id);
        queries
            .into_iter()
            .map(|q| {
                let q = q.decompress().unwrap();
                share
                    .apply_query_and_lagrange_coefficient(q, &coeff)
                    .compress()
            })
            .collect()
    }
}
