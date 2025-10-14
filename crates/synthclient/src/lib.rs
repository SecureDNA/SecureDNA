// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod api;
pub mod fetch;
pub mod ncbi;
pub mod parsefasta;
pub mod rate_limiter;
pub mod retry_if;

#[cfg(feature = "native")]
pub mod recaptcha;

#[cfg(feature = "native")]
pub mod web_cache;

#[cfg(feature = "native")]
pub mod server_selection;

#[cfg(feature = "native")]
pub mod shims;
