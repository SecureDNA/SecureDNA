// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Deserializer;
use serde_json::Value;

/// Deserialize a boolean, treating `"true"` as `true` and `"false"` as `false`.
pub fn bool_or_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    match serde::de::Deserialize::deserialize(deserializer)? {
        Value::Bool(b) => Ok(b),
        Value::String(s) if s == "true" => Ok(true),
        Value::String(s) if s == "false" => Ok(false),
        _ => Err(serde::de::Error::custom("Expected boolean")),
    }
}
