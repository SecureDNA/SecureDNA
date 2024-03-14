// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

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
        // A 60 BP sequence should have 31 forward runt hashes, 19 forward hog hashes, and 1 forward AA hash.
        // Each additional BP should 3 additional hashes.
        // And RC should double all that.
        // Hence `hashes = 2 * (3*(bp - 60) + 31 + 19 + 1)` = 6*bp - 258 so bp = (hashes + 258)/6
        // In the test framework we never generate samples smaller than 60BPs
        BasePairCount((self.0 + 258) / 6)
    }
}
