// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A compact encoding of a set of `RistrettoPoint`-like types in a flat `Vec<u8>`
//! Includes a type field, length, and checksum for data validation.

pub mod datatype;
pub mod error;
pub mod packable;

pub use datatype::PackedRistrettos;
pub use error::DeserializeError;
pub use packable::PackableRistretto;
