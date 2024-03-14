// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// For timestamps, we use the time crate's implementation of ISO 8601 with default config.
///
/// In default config:
/// - The time has precision to the second and nine decimal digits.
///
/// So the width is fixed, unlike the default `Display` impl.

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! info_with_timestamp {
    ($fmt:expr $(, $args:expr)*) => {
        shared_types::log::info!(concat!("{_when}: ", $fmt) $(, $args)*,
            _when=shared_types::time::OffsetDateTime::now_utc().format(&shared_types::time::format_description::well_known::Iso8601::DEFAULT).unwrap())
    };
}

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! info_with_timestamp {
    ($fmt:expr $(, $args:expr)*) => {
        shared_types::log::info!($fmt $(, $args)*)
    };
}

/// Looks like this is only called in doprf_client. log dep is no longer called in doprf_client,
/// only here in shared_types::logging.
#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! debug_with_timestamp {
    ($fmt:expr $(, $args:expr)*) => {
        shared_types::log::debug!(concat!("{_when}: ", $fmt) $(, $args)*,
            _when=shared_types::time::OffsetDateTime::now_utc().format(&shared_types::time::format_description::well_known::Iso8601::DEFAULT).unwrap())
    };
}

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! debug_with_timestamp {
    ($fmt:expr $(, $args:expr)*) => {
        shared_types::log::debug!($fmt $(, $args)*)
    };
}
