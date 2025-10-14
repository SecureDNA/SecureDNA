// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A Rust implementation of "distributed oblivious pseudo-random functions"
//! (DOPRF), as described in [_Efficient Maliciously Secure Oblivious
//! Exponentiations_](https://eprint.iacr.org/2024/1613) (Baum et al, 2024).
//!
//! This implementation uses
//! [`curve25519-dalek`](https://doc.dalek.rs/curve25519_dalek/)'s _Ristretto_
//! group as the group 𝔾, and SHA3-256 in combination with
//! `RistrettoPoint::from_hash` as the random oracle to 𝔾.
//!
//! This crate only implements the computations from the paper. `doprf_client` in the
//! SecureDNA monorepo performs the actual networking, using a protocol specific to
//! SecureDNA that is not strictly part of DOPRF.
//!
//! ## Key Registration
//!
//! The `genkey` and `genkeyshares` utilities in [`shims`] implement Key
//! Registration. Commitments for _active security_ can be initialized using
//! `genactivesecuritykey`. For example:
//!
//! ```sh
//! $ cargo run --bin genkey
//! abcd
//!
//! $ cargo run --bin genkeyshares -- --keyholders-required 3 --num-keyholders 3 abcd
//! 1111
//! 2222
//! 3333
//!
//! $ cargo run --bin genactivesecuritykey -- --keyholders-required 3 --keyshares 1111,2222,3333 abcd
//! aaaa
//! bbbb
//! cccc
//! ```
//!
//! ## API usage
//!
//! In the keyserver code, generated key shares can be loaded with
//! [`KeyShare::from_str`](prf::KeyShare).
//!
//! _Active security_ commitments can be loaded by all parties using
//! [`ActiveSecurityKey::from_commitments`](active_security::ActiveSecurityKey::from_commitments).
//!
//! A client negotiates a [`KeyserverIdSet`](party::KeyserverIdSet) for a quorum
//! of keyserver IDs, then calls [`queryset::setup_queries`] to make
//! [`CompressedQuery`](prf::CompressedQuery) objects (Ristretto hashes) to send
//! to the keyservers.
//!
//! A keyserver responds to such requests using
//! [`KeyserverIdSet::langrange_coefficient_for_id`](party::KeyserverIdSet::langrange_coefficient_for_id)
//! and
//! [`KeyShare::apply_query_and_lagrange_coefficient`](prf::KeyShare::apply_query_and_lagrange_coefficient),
//! yielding an oblivious [`CompressedHashPart`](prf::CompressedHashPart).
//!
//! The client recombines these responses using
//! [`QueriesSecurityContext::recombine`](queryset::QueriesSecurityContext::recombine).
//!
//! For an example, see the `keyshares_agree_with_original_key` test in
//! [`src/shims/genkeyshares.rs`](../src/doprf/shims/genkeyshares.rs.html), or
//! the `keyserver` and `doprf_client` crates in the [SecureDNA
//! monorepo](https://github.com/SecureDNA/SecureDNA).

#[macro_use]
pub mod prf;

pub mod active_security;
pub mod batch;
mod blinding;
pub mod lagrange;
pub mod party;
pub mod queryset;
pub mod shims;
pub mod tagged;
mod verification;

pub use blinding::Blinder;
pub use verification::{VerificationFailure, Verifier};

#[cfg(test)]
pub(crate) mod testutil;
