// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Callbacks/etc that are likely to useful for typical servers

use std::io::ErrorKind::InvalidData;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use anyhow::Context;
use hyper::{body::Incoming, Method, Request, StatusCode};
use rustls::crypto::ring;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use super::traits::{
    AppConfig, AppState, ListenFn, Listener, LoadConfigFn, ReadFileFn, RelativeConfig, ResponseFn,
    ValidServerSetup,
};
use super::{ExternalWorld, MultiplaneServer, ServerConfig};
use crate::error::ErrWrapper;
use crate::response::{text, GenericResponse};
use crate::signal::{
    fast_shutdown_requested, graceful_shutdown_requested, reload_config_requested,
};

/// Runs a server exposed to the world with common defaults
///
/// This runs a server with the following behaviors:
/// * The configuration is loaded from a TOML file at `config_path`.
/// * `SIGHUP`s are interpreted as requests to reload the config.
/// * The first `SIGINT` is interpreted as a request to gracefully shut down the server.
/// * `SIGHUP`s or multiple `SIGINT`s are interpreted as a request to quickly shut down the server.
/// * [`default_control_plane`] is used, meaning that if the config file specifies a
///   control plane address, anyone with access to that address can trigger reloads and shutdowns.
///
/// This may error out on startup due to e.g. a bad config or port conflict, but should not produce
/// errors once running.
///
/// **BEWARE:** This alters process state by _permanently_ registering an interrupt handler
/// through [`tokio`]. As such, this should probably only be called near the entry point to
/// a program, not by a library. Likewise, it also installs a default crypto implementation.
pub async fn run_server<AC: AppConfig, AS: AppState>(
    load_cfg: impl LoadConfigFn<ServerConfig<AC>>,
    server_setup: impl ValidServerSetup<AC, AS>,
) -> anyhow::Result<()> {
    if ring::default_provider().install_default().is_err() {
        warn!("Unable to install rustls default CryptoProvider. (did something configure it already?)");
    }

    let external_world = ExternalWorld {
        listen: default_listen_fn,
        load_cfg,
        read_file: tokio::fs::read,
    };

    let server = Arc::new_cyclic(|server| {
        server_setup
            .to_server_setup()
            .with_response_to_control(default_control_plane(server.clone()))
            .build_with_external_world(external_world)
    });

    server.reload_cfg().await?;

    let reload = async {
        loop {
            reload_config_requested().await;
            info!("Config reload signaled");
            if let Err(err) = server.reload_cfg().await {
                error!("Unable to reload config: {err:?}");
            }
        }
    };

    let graceful_shutdown = async {
        graceful_shutdown_requested().await;
        info!("Graceful shutdown signaled");
        server.graceful_shutdown().await;
        futures::future::pending().await
    };

    tokio::select! {
        biased;
        _ = fast_shutdown_requested() => info!("Fast shutdown requested..."),
        () = graceful_shutdown => {}
        _ = reload => {}
        _ = server.serve() => {}
    };

    Ok(())
}

/// [`ResponseFn`] that just informs the client the service is disabled
pub async fn disabled_service<AS>(
    _app_state: AS,
    _addr: SocketAddr,
    _req: Request<Incoming>,
) -> GenericResponse {
    text(StatusCode::NOT_FOUND, "Service not set up.\n")
}

/// Default control plane, allowing server to be reloaded or shut down.
///
/// Given a [`Weak`] reference to a [`MultiplaneServer`], controls the server in response to
/// HTTP requests:
///
/// * `POST`ing to `/reload` causes the server to reload its config.
/// * `POST`ing to `/shutdown` causes the server to start a graceful shutdown.
pub fn default_control_plane<AS: AppState>(server: Weak<MultiplaneServer>) -> impl ResponseFn<AS> {
    move |_state, _addr, request| {
        let server = server.clone();
        async move {
            let Some(server) = Weak::upgrade(&server) else {
                // Eh, I don't think this should be possible because the MPServer
                // shouldn't terminate while this is executing.
                error!("Unable to obtain server reference for control plane.");
                return text(StatusCode::INTERNAL_SERVER_ERROR, "Can't access ourself.\n");
            };

            match (request.method(), request.uri().path()) {
                (&Method::POST, "/reload") => match server.as_ref().reload_cfg().await {
                    Ok(()) => text(StatusCode::OK, "Configuration reload completed.\n"),
                    Err(err) => {
                        error!("Unable to reload config: {err:?}");
                        text(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unable to reload configuration:\n{err:?}\n"),
                        )
                    }
                },
                (&Method::POST, "/shutdown") => {
                    server.as_ref().graceful_shutdown().await;
                    text(StatusCode::OK, "Graceful shutdown initiated.\n")
                }
                _ => text(StatusCode::NOT_FOUND, "Invalid control URI.\n"),
            }
        }
    }
}

/// External world that listens on ports and reads configs from TOML files
pub fn default_external_world<C: DeserializeOwned + RelativeConfig>(
    path: impl AsRef<Path>,
) -> ExternalWorld<impl ListenFn, impl LoadConfigFn<C>, impl ReadFileFn> {
    ExternalWorld {
        listen: default_listen_fn,
        load_cfg: toml_reader(path),
        read_file: tokio::fs::read,
    }
}

/// Default [`ListenFn`] implementation that opens actual ports.
pub async fn default_listen_fn(address: SocketAddr) -> std::io::Result<impl Listener> {
    let tcp_listener = TcpListener::bind(address)
        .await
        .map_err(add_advice_for_port(address.port()))?;
    Ok(new_tcp_listener(Arc::new(tcp_listener)))
}

/// Creates a [`Listener`] from a [`tokio::net::TcpListener`].
pub fn new_tcp_listener(tcp_listener: Arc<TcpListener>) -> impl Listener {
    move || {
        futures::stream::unfold(tcp_listener.clone(), |listener| async {
            Some((listener.accept().await, listener))
        })
    }
}

/// Default [`LoadConfigFn`] that reads and parses configs from TOML files.
pub fn toml_reader<C: DeserializeOwned + RelativeConfig>(
    path: impl AsRef<Path>,
) -> impl LoadConfigFn<C, Error = ErrWrapper> {
    let path = path.as_ref().to_owned();
    move || {
        let path = path.clone();
        async move {
            let config = tokio::fs::read(&path)
                .await
                .with_context(|| format!("Couldn't open config TOML: {path:?}"))?;
            let mut hash = Sha256::new();
            hash.update(&config);
            let config = String::from_utf8(config)
                .map_err(|err| std::io::Error::new(InvalidData, err))
                .with_context(|| format!("Couldn't interpret config TOML as UTF-8: {path:?}"))?;
            let config: C = toml::from_str(&config)
                .map_err(|err| std::io::Error::new(InvalidData, err))
                .with_context(|| format!("Couldn't parse as TOML: {path:?}"))?;
            let parent_path = path.parent().unwrap_or(".".as_ref());
            let config = config.relative_to(parent_path);
            Ok((config, hash))
        }
    }
}

/// [`LoadConfigFn`] implementation that wraps a simple infallible closure.
///
/// Primarily useful for testing.
pub fn stub_cfg<AC>(
    build_cfg: impl 'static + Clone + Send + Fn() -> AC,
) -> impl LoadConfigFn<AC, Error = std::convert::Infallible> {
    move || {
        let build_cfg = build_cfg.clone();
        async move { Ok((build_cfg(), Sha256::new())) }
    }
}

/// [`ReadFileFn`] implementation that never reads from disk.
///
/// Primarily useful for testing.
pub async fn read_no_disk(_path: PathBuf) -> std::io::Result<Vec<u8>> {
    Err(std::io::ErrorKind::NotFound.into())
}

/// Appends end-user hints to [`std::io::Error`].
///
/// Our userbase includes people who may be unfamiliar with Linux's restrictions on low ports.
/// This returns a function that tweaks [`std::io::Error`]s to add a hint when permission is
/// denied for listening on privileged ports.
pub fn add_advice_for_port(port: u16) -> impl Fn(std::io::Error) -> std::io::Error {
    move |err| match advice_for_port(port, &err) {
        Some(hint) => std::io::Error::new(err.kind(), ErrHint { inner: err, hint }),
        None => err,
    }
}

fn advice_for_port(port: u16, error: &std::io::Error) -> Option<&'static str> {
    if cfg!(target_os = "linux")
        && error.kind() == std::io::ErrorKind::PermissionDenied
        && port < 1024
    {
        return Some("(ports under 1024 usually require admin privileges)");
    }
    None
}

#[derive(Debug)]
struct ErrHint {
    inner: std::io::Error,
    hint: &'static str,
}

impl std::error::Error for ErrHint {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl std::fmt::Display for ErrHint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}\n{}", self.inner, self.hint)
    }
}
