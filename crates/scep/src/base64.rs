// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use base64::{engine::general_purpose, Engine};

/// The STANDARD (with padding) engine that we use everywhere in SCEP
pub const B64: general_purpose::GeneralPurpose = general_purpose::STANDARD;

/// Encode a base64 str using the standard alphabet and padding
pub fn encode(data: impl AsRef<[u8]>) -> String {
    B64.encode(data)
}

/// Decode a base64 str using the standard alphabet and padding
pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64.decode(s)
}
