// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[macro_export]
#[cfg(feature = "env_passphrase")]
macro_rules! certificate_client_version {
    () => {
        concat!(env!("CARGO_PKG_VERSION"), " (env_passphrase)")
    };
}

#[macro_export]
#[cfg(not(feature = "env_passphrase"))]
macro_rules! certificate_client_version {
    () => {
        env!("CARGO_PKG_VERSION")
    };
}
