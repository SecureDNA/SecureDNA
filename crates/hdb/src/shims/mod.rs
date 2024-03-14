// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod genindex;
pub mod unused_hlt_indices;

#[cfg(not(feature = "centralized_keygen"))]
pub mod unimplemented;

#[cfg(feature = "centralized_keygen")]
pub mod genhdb;
#[cfg(not(feature = "centralized_keygen"))]
pub use unimplemented as genhdb;
