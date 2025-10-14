// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod api_client;
pub mod body;
pub mod error;
pub mod service;
mod status_code;

pub use api_client::BaseApiClient;
pub use error::{HttpError, UnusableRequestId};
pub use service::portable::{securedna_service_and_worker, service_and_worker};
