// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub fn get_version() -> String {
    format!("{}-{}", env!("CARGO_PKG_VERSION"), env!("VERGEN_GIT_SHA"))
}
