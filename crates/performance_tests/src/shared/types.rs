// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use shared_types::WINDOW_LENGTH_AA;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct HashCount(pub usize);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct BasePairCount(pub usize);

// Specifies the default request size in hashes. Each hash is 32 bytes.
// this number needs to be divisible for 6 for a comparable transformation into BPs
const DEFAULT_HASH_COUNT: HashCount = HashCount(5742);

impl HashCount {
    pub fn get_default() -> HashCount {
        DEFAULT_HASH_COUNT
    }

    /// Apply the magical conversion formula between HashCount and BasePairCount
    /// WARNING: this formula can change if the `synthclient` generates more or less hashes
    pub fn to_bp_count(&self) -> BasePairCount {
        // To understand these magical numbers, see the following example:
        // A 60 BP sequence should have 31 forward runt hashes, 19 forward hog hashes, and
        // (60 - 3 * WINDOW_LENGTH_AA + 1) forward AA hashes (one per AA window along the sequence).
        // Each additional BP should add 3 additional hashes.
        // And RC should double all that.
        // Let W = WINDOW_LENGTH_AA. Forward hashes: shingled runt (30 bp), shingled hog (42 bp), AA (3*W bp):
        //  (bp - 30 + 1) + (bp - 42 + 1) + (bp - 3*W + 1) = 3*bp - 69 - 3*W.
        // Hence `hashes = 2 * (3*bp - 69 - 3*W)` = 6*bp - 138 - 6*W, so bp = (hashes + 138 + 6*W) / 6.
        // In the test framework we never generate samples smaller than 60BPs
        BasePairCount((self.0 + 138 + 6 * WINDOW_LENGTH_AA) / 6)
    }
}
