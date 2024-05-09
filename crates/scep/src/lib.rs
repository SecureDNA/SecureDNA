// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod base64;
pub mod cookie;
pub mod error;
pub mod mutual_authentication;
pub mod nonce;
pub mod states;
pub mod steps;
pub mod types;

pub const OPEN_ENDPOINT: &str = "/scep/open";
pub const AUTHENTICATE_ENDPOINT: &str = "/scep/authenticate";
pub const KEYSERVE_ENDPOINT: &str = "/scep/keyserve";
pub const SCREEN_ENDPOINT: &str = "/scep/screen";
pub const SCREEN_WITH_EL_ENDPOINT: &str = "/scep/screen-with-EL";
pub const ELT_ENDPOINT: &str = "/scep/ELT";
pub const ELT_SEQ_HASHES_ENDPOINT: &str = "/scep/ELT-seq-hashes";
pub const ELT_SCREEN_HASHES_ENDPOINT: &str = "/scep/ELT-screen-hashes";
