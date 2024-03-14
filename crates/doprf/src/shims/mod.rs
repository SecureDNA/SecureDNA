// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(not(feature = "centralized_keygen"))]
pub mod unimplemented;

#[cfg(feature = "centralized_keygen")]
pub mod genkey;

#[cfg(not(feature = "centralized_keygen"))]
pub use unimplemented as genkey;

#[cfg(feature = "centralized_keygen")]
pub mod genkeyshares;
#[cfg(not(feature = "centralized_keygen"))]
pub use unimplemented as genkeyshares;

#[cfg(feature = "centralized_keygen")]
pub mod genactivesecuritykey;

#[cfg(not(feature = "centralized_keygen"))]
pub use unimplemented as genactivesecuritykey;
