// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod api_client;
pub mod api_client_core;
pub mod error;

pub use api_client::{BaseApiClient, HttpsToHttpRewriter};
pub use api_client_core::test_utils;
pub use error::HttpError;
