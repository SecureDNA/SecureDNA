// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shutdown signal detection

use tokio::signal::ctrl_c;

/// Future that resolves when a config reload has been requested.
///
/// Detects a `SIGHUP`.
///
/// **BEWARE:** This alters process state by _permanently_ registering an interrupt handler
/// through [`tokio`]. As such, this should probably only be called near the entry point to
/// a program, not by a library. Also, the usual caveats around signals apply; they may only
/// be detected after this is first called, multiple signals may be collapsed, etc.
///
/// # Panics
///
/// In theory, this can panic when things in [`tokio::signal`] error out, but...
/// realistically, the docs only describe that as happening when lower-level things
/// fail "for some reason".
pub async fn reload_config_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sighup = signal(SignalKind::hangup()).expect("Can't register SIGHUP handler");
        sighup.recv().await;
    }

    // Windows doesn't have an equivalent to SIGHUP.
    #[cfg(not(unix))]
    std::future::pending::<()>().await;
}

/// Future that resolves when a graceful shutdown has been requested.
///
/// Detects a `SIGINT`.
///
/// **BEWARE:** This alters process state by _permanently_ registering an interrupt handler
/// through [`tokio`]. As such, this should probably only be called near the entry point to
/// a program, not by a library. Also, the usual caveats around signals apply; they may only
/// be detected after this is first called, multiple signals may be collapsed, etc.
///
/// # Panics
///
/// In theory, this can panic when things in [`tokio::signal`] error out, but...
/// realistically, the docs only describe that as happening when lower-level things
/// fail "for some reason".
pub async fn graceful_shutdown_requested() {
    ctrl_c().await.expect("Unable to await CTRL-C");
}

/// Future that resolves when a fast shutdown has been requested.
///
/// Things that constitute a request for a fast shutdown:
///
/// * Multiple `SIGINT`s
/// * At least one `SIGTERM`
///
/// **BEWARE:** This alters process state by _permanently_ registering an interrupt handler
/// through [`tokio`]. As such, this should probably only be called near the entry point to
/// a program, not by a library. Also, the usual caveats around signals apply; they may only
/// be detected after this is first called, multiple signals may be collapsed, etc.
///
/// # Panics
///
/// In theory, this can panic when things in [`tokio::signal`] error out, but...
/// realistically, the docs only describe that as happening when lower-level things
/// fail "for some reason".
pub async fn fast_shutdown_requested() {
    let want_to_shutdown = async {
        ctrl_c().await.expect("Unable to await CTRL-C");
        ctrl_c().await.expect("Unable to await CTRL-C");
    };

    #[cfg(unix)]
    let want_to_shutdown = async {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).expect("Can't register SIGTERM handler");
        tokio::select! {
            _ = want_to_shutdown => {},
            _ = sigterm.recv() => {},
        };
    };

    want_to_shutdown.await
}

// Automated testing of signals seems... not fun. Registering a signal handler is permanent and
// global, completely destroying test isolation. In an ideal world, we'd test by forking off
// child processes, but... Rust isn't a huge fan of forking. For now, I've just written an example
// program named `signal`, and manually tested it. Hopefully the behavior  of these functions is
// simple enough (and changes rarely enough) that manual testing is acceptable.
