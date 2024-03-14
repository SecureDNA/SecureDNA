// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate is used for types that are shared within this repo's crates

// log and time crates are used in macros, so `pub use` here for easier referencing
pub use log;
pub use time;

pub mod hash;
pub mod hdb;
#[cfg(feature = "http")]
pub mod http;
pub mod logging;
pub mod metrics;
pub mod requests;
pub mod server_selection;
pub mod server_versions;
pub mod synthesis_permission;

pub use hash::{WINDOW_LENGTH_AA, WINDOW_LENGTH_DNA_NORMAL, WINDOW_LENGTH_DNA_RUNT};
