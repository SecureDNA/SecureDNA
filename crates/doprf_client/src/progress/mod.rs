// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg_attr(target_arch = "wasm32", path = "wasm.rs")]
#[cfg_attr(not(target_arch = "wasm32"), path = "native.rs")]
pub mod implementation;

pub use self::implementation::*;
