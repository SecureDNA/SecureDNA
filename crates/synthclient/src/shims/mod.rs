// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(not(target_arch = "wasm32"))]
pub mod event_store;
#[cfg(not(target_arch = "wasm32"))]
pub mod server;

pub mod types;
