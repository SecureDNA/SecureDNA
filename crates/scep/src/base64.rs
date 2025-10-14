// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
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

/// Like [`decode`] but decodes into an array, avoiding allocations.
pub fn decode_array<const N: usize>(
    data: impl AsRef<[u8]>,
) -> Result<[u8; N], base64::DecodeSliceError> {
    let data = data.as_ref();
    let mut output = [0; N];
    let written = B64.decode_slice(data, &mut output)?;
    if written != N {
        return Err(base64::DecodeSliceError::DecodeError(
            base64::DecodeError::InvalidLength(data.len()),
        ));
    }
    Ok(output)
}
