// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use doprf::active_security::Commitment;
use doprf::prf::{CompletedHashValue, HashPart, Query};
use doprf::tagged::TaggedHash;

/// Denotes HTTP content-type of streamed ristrettos containing `Self`.
pub trait HasContentType {
    const CONTENT_TYPE: &'static str;
}

impl HasContentType for Query {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-queries; version=1.0";
}

impl HasContentType for HashPart {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-hash-parts; version=1.0";
}

impl HasContentType for CompletedHashValue {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-hashes; version=1.0";
}

impl HasContentType for Commitment {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-target-contribution; version=1.0";
}

impl HasContentType for TaggedHash {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-tagged-hashes; version=1.0";
}
