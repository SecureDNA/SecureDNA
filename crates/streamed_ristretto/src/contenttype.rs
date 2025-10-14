// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use doprf::active_security::CompressedCommitment;
use doprf::prf::{CompressedCompletedHashValue, CompressedHashPart, CompressedQuery};
use doprf::tagged::TaggedHash;

/// Denotes HTTP content-type of streamed ristrettos containing `Self`.
pub trait HasContentType {
    const CONTENT_TYPE: &'static str;
}

impl HasContentType for CompressedQuery {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-queries; version=1.0";
}

impl HasContentType for CompressedHashPart {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-hash-parts; version=1.0";
}

impl HasContentType for CompressedCompletedHashValue {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-hashes; version=1.0";
}

impl HasContentType for CompressedCommitment {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-target-contribution; version=1.0";
}

impl HasContentType for TaggedHash {
    const CONTENT_TYPE: &'static str = "application/x-ristretto-tagged-hashes; version=1.0";
}
