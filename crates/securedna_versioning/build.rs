// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use vergen::EmitBuilder;

fn main() {
    EmitBuilder::builder().git_sha(true).emit().unwrap();
}
