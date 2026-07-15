// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::IsTerminal;

use tracing::Level;
use tracing_subscriber::EnvFilter;

/// Setup [`tracing`] with defaults for SecureDNA binaries.
///
/// The default log level is [`INFO`](Level::INFO), but it can be overridden with the usual rust
/// logging env var (`RUST_LOG`). Color is disabled if either stdout or stderr are redirected to
/// a file.
pub fn init_from_env() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();
    let is_terminal = std::io::stdout().is_terminal() && std::io::stderr().is_terminal();
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_ansi(is_terminal)
        .init();
}
