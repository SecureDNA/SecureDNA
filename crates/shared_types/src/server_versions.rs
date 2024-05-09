// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyserverVersion {
    /// A string containing the cargo version & git SHA
    pub server_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Type returned from the HDB /version endpoint.
pub struct HdbVersion {
    /// A string containing the cargo version & git SHA
    pub server_version: String,
    /// Timestamp this HDB was generated.
    /// `None` if unknown.
    pub hdb_timestamp: Option<String>,
}
