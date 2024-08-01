// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use futures::{future::Either, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use tokio::sync::{mpsc, watch};
use tracing::{info, info_span, warn, Instrument};

use super::tls::{redirect_to_https, terminate_tls_to_listener, TlsConfig};
use super::traits::{
    either_response_fn, AppConfig, AppState, ConnectedFn, ConnectionFailedFn, ConnectionState,
    DisconnectedFn, ListenFn, Listener, ReadFileFn, RelativeConfig, ResponseFn, ValidExternalWorld,
    ValidServerSetup,
};
use super::{MissingCallback, ServerSetup};
use crate::server::Server;

/// HTTP server with common behaviors for SecureDNA
///
/// This kind of HTTP server provides three planes:
/// * `main`: The primary service provided by this HTTP server, which untrusted clients
///   connect to.
/// * `monitoring`: Used for collecting statistics about the server's operation.
/// * `control`: Used for triggering config reloads and shutdowns.
///
/// The `main` plane is mandatory, but the `monitoring` and `control` planes are optional.
/// Each active plane must served on its own address/port combination.
///
/// The server has an inherent notion of configuration and the ability to gracefully
/// reload said configuration (see [`reload_cfg`](Self::reload_cfg)), as well as gracefully
/// shut down (see [`graceful_shutdown`](Self::graceful_shutdown)).
///
/// The initial server setup (perhaps via [`MultiplaneServer::new`]) is infallible, making it
/// easier to use [`Arc::new_cyclic`], so a config must be loaded via
/// [`reload_cfg`](Self::reload_cfg) after the server is setup but before calling
/// [`serve`](Self::serve). Without an active config, [`serve`](Self::serve) does nothing.
pub struct MultiplaneServer {
    states: tokio::sync::Mutex<AppStateTransitionInfo>,
    bundled_servers_rx: watch::Receiver<Option<Arc<BundledServer>>>,
}

/// Contains info used during calls to [`MultiplaneServer::update_state_and_synchronize`].
///
/// This is primarily grouped together in a single struct because it all gets used together and
/// stuck in the same mutex.
struct AppStateTransitionInfo {
    /// Attempts to load a new config, interpret it as app state, then send it to
    /// [`MultiplaneServer::bundled_servers_rx`].
    ///
    /// The steps pass custom types to each other so we group them all together into a larger
    /// closure with an API that lacks custom types. Note that this closure caches listeners
    /// between calls; returning successfully means the cache has been updated and a new
    /// bundled server has been sent to [`MultiplaneServer::bundled_servers_rx`].
    update_server: Box<dyn UpdateServerFn>,
    /// Used for detecting if if the previous app-state/[`ServerConfig`] are still listening on ports.
    ///
    /// By the time an [`mpsc::Receiver`] makes its way to this variable, the only
    /// [`mpsc::Sender`]s for this should only exist in active [`BundledServer::serve_fn`]
    /// that haven't yet had [`BundledServer::graceful_shutdown`] called.
    previous_state_listeners: mpsc::Receiver<()>,
    /// Tracks the current app-state/[`ServerConfig`]s listeners.
    ///
    /// This isn't directly used; it's held until [`Self::previous_state_listeners`] needs it.
    latest_state_listeners: mpsc::Receiver<()>,
}

#[derive(thiserror::Error, Debug)]
#[error("Main service plane had no address/port.")]
struct MainPlaneDisabled;

impl MultiplaneServer {
    /// Creates a new [`ServerSetup`] with a few defaults.
    pub fn builder() -> ServerSetup<
        MissingCallback,
        MissingCallback,
        MissingCallback,
        MissingCallback,
        impl ConnectedFn<ConnectionState = ()>,
        impl ConnectionFailedFn,
        impl DisconnectedFn<()>,
    > {
        ServerSetup::new()
    }

    /// Creates a new [`MultiplaneServer`].
    ///
    /// The parameters are grouped into two types:
    /// * [`ServerSetup`] which represents application-specific settings, primarily how to respond
    ///   HTTP requests and handling reloading configs. For convenience, you may construct a
    ///   [`ServerSetup`] via [`MultiplaneServer::builder`].
    /// * [`ExternalWorld`] which represents how the [`MultiplaneServer`] should attempt to
    ///   interface with the world around it. If you're not testing, you should probably just use
    ///   [`run_server`](super::common::run_server).
    pub fn new<AC: AppConfig, AS: AppState>(
        server_setup: impl ValidServerSetup<AC, AS>,
        external_world: impl ValidExternalWorld<ServerConfig<AC>>,
    ) -> Self {
        let server_setup = server_setup.to_server_setup();
        let external_world = external_world.to_external_world();
        let (bundled_servers_tx, bundled_servers_rx) = watch::channel(None);

        let update_server = Box::new(Self::server_updater(
            server_setup,
            external_world,
            bundled_servers_tx,
        ));

        let (_tx, previous_state_listeners) = mpsc::channel(1);
        let (_tx, latest_state_listeners) = mpsc::channel(1);
        let states = tokio::sync::Mutex::new(AppStateTransitionInfo {
            update_server,
            previous_state_listeners,
            latest_state_listeners,
        });

        Self {
            states,
            bundled_servers_rx,
        }
    }

    /// Runs all planes until shutdown.
    ///
    /// This runs all planes (main, monitoring, control), updating in response to
    /// reconfigurations and shutting down once graceful_shutdown is called. Note that
    /// [`reload_cfg`](Self::reload_cfg) must be called at least once before starting
    /// this or it will be a no-op.
    pub async fn serve(&self) {
        let mut servers_rx = self.bundled_servers_rx.clone();
        servers_rx.mark_changed();

        let old_server = Arc::new(BundledServer::default());
        let mut ran_server = false;

        futures::stream::unfold(
            (servers_rx, old_server),
            |(mut servers_rx, old_server)| async {
                servers_rx
                    .changed()
                    .await
                    .expect("Impossible: Can't drop mpserver while .serve() runs");
                let Some(new_server) = servers_rx.borrow_and_update().clone() else {
                    old_server.graceful_shutdown().await;
                    return None;
                };

                let new_server2 = new_server.clone();
                let fut = async move {
                    tokio::join!(old_server.graceful_shutdown(), new_server2.serve());
                };

                Some((fut, (servers_rx, new_server)))
            },
        )
        .for_each_concurrent(None, |f| {
            ran_server = true;
            f
        })
        .await;

        if !ran_server {
            warn!("serve() called without configuration; doing nothing");
        }
    }

    /// Reloads the server config.
    ///
    /// This blocks until it's known that the config reload should be successful and appropriate
    /// ports have been opened/closed, but before old connections finish.
    ///
    /// If an error occurs while attempting to reload the config (for example if the config file
    /// is unreadable or the server encounters a port conflict), then the config change isn't
    /// applied, and the server will continue running the old config completely uninterrupted.
    /// Any errors that occur while reloading the config are returned by this method.
    ///
    /// The process for updating config is:
    /// * [`ExternalWorld.load_cfg`](ExternalWorld::load_cfg) is responsible for reading and
    ///   parsing a config file into some kind of inert application configuration (of generic
    ///   type `AC`, specified by your application).
    /// * The application configuration (of type `AC`) is supplied to
    ///   [`ServerSetup.reconfigure`](ServerSetup::reconfigure) along with the current application
    ///   state (if it exists). [`ServerSetup.reconfigure`](ServerSetup::reconfigure) must then
    ///   interpret the inert config to produce some kind of application state (of generic type
    ///   `AS`, specified by your application) containing settings and resources (caches, open
    ///   files etc).
    /// * Once all that is successful, the configuration change is complete. From now on any _new_
    ///   connections will have the new application state passed as the first argument to
    ///   whichever [`ResponseFn`] is suppling HTTP responses. Existing connections will keep
    ///   using the old application state until they they close. Note that this means any number
    ///   of versions of application state may be active at any time (if the config is frequently
    ///   reloaded and connections are long-lived).
    pub async fn reload_cfg(&self) -> anyhow::Result<()> {
        let mut states = self.states.lock().await;
        match Self::update_state_and_synchronize(&mut states, SyncAction::ReloadCfg).await? {
            Some(hash) => info!(
                "Config successfully loaded with SHA-256: {}",
                hex::encode(hash.finalize())
            ),
            None => warn!("Bug: Somehow config reloaded but didn't produce hash."),
        }
        Ok(())
    }

    /// Shuts down server.
    ///
    /// Returns once the shutdown signal has been recieved.
    pub async fn graceful_shutdown(&self) {
        let mut states = self.states.lock().await;
        Self::update_state_and_synchronize(&mut states, SyncAction::Shutdown)
            .await
            .expect("We're not listening so no errors should occur");
    }

    // TODO: full sync to block until old connections are gone... probably would work by
    // adding an additional tracker to the bundled server itself?

    // This updates states in such a way that rapidly changing addresses shouldn't lead to
    // any race conditions where the server attempts to listen on a port it's already holding.
    // Normally that could happen if a run() instance were holding a port and then you switched
    // to another address and back before the run() had a chance to update; you could end up
    // attempting to listen on an address run() was already holding. We avoid that by bundling
    // listeners with MPSC senders so we can wait for them to stop existing before we attempt
    // another state-change.
    async fn update_state_and_synchronize(
        states: &mut AppStateTransitionInfo,
        action: SyncAction,
    ) -> anyhow::Result<Option<Sha256>> {
        // Ensure we don't start a new state change until all self.run() calls have let go
        // of the previous listeners. Although this looks redundant WRT the last statement,
        // it's actually necessary because the last statement could have been canceled.
        states.previous_state_listeners.recv().await;

        let (tracker, listeners_active) = mpsc::channel(1);

        let hash = (states.update_server)(action, tracker).await?;

        // Ok, given that states.update_server didn't error out, we know the state transition
        // is guaranteed to be successful; we can finally engage in side-effects.

        // It's fine to overwrite/discard previous_state_listeners because the first line of this
        // function checked that it had no more listeners and no more could have been created in
        // the intervening time because there were none to clone.
        states.previous_state_listeners =
            std::mem::replace(&mut states.latest_state_listeners, listeners_active);

        // Don't return until the previous version has stopped listening.
        states.previous_state_listeners.recv().await;

        Ok(hash)
    }

    fn server_updater<AC: AppConfig, AS: AppState>(
        server_setup: impl ValidServerSetup<AC, AS>,
        external_world: impl ValidExternalWorld<ServerConfig<AC>>,
        bundled_servers_tx: watch::Sender<Option<Arc<BundledServer>>>,
    ) -> impl UpdateServerFn {
        let server_setup = server_setup.to_server_setup();
        let external_world = external_world.to_external_world();
        // For seamless re-use of sockets
        // By storing these in the closure rather than the MPServer,
        // we avoid making the server depend on the listener type.
        let listener_cache: Arc<tokio::sync::Mutex<SmallVec<[_; 3]>>> = Arc::default();
        let latest_app_state: Arc<tokio::sync::Mutex<Option<Arc<AS>>>> = Arc::default();
        let bundled_servers_tx = Arc::new(bundled_servers_tx);

        move |sync_action, tracker| {
            let server_setup = server_setup.clone();
            let external_world = external_world.clone();
            let listener_cache = listener_cache.clone();
            let latest_app_state = latest_app_state.clone();
            let bundled_servers_tx = bundled_servers_tx.clone();
            Box::pin(async move {
                let mut listener_cache = listener_cache.lock().await;
                let mut latest_app_state = latest_app_state.lock().await;
                let mut listener_cache_updater =
                    ListenerCacheUpdater::new(external_world.listen, &mut listener_cache);

                if sync_action == SyncAction::Shutdown {
                    listener_cache_updater.update();
                    *latest_app_state = None;
                    bundled_servers_tx.send_replace(None);
                    return Ok(None);
                }

                let prev_state = match &*latest_app_state {
                    Some(ref state) => Arc::downgrade(state),
                    None => Weak::new(),
                };

                let (app_config, hash) = (external_world.load_cfg)().await?;
                let server_config = app_config.clone_without_custom();
                let reconfigure = server_setup.reconfigure.clone();
                let state = reconfigure(app_config, prev_state).await?;

                // TODO: detect address conflicts between new addrs so we don't end up with
                // confusing server behavior of e.g. requests going to random planes

                let bundled_server = BundledServer::new(
                    state.clone(),
                    server_setup,
                    &mut listener_cache_updater,
                    external_world.read_file,
                    server_config,
                    tracker,
                )
                .await?;

                // At this point, the update should be guaranteed to be successful.
                listener_cache_updater.update();
                *latest_app_state = Some(state);
                bundled_servers_tx.send_replace(Some(Arc::new(bundled_server)));
                Ok(Some(hash))
            })
        }
    }
}

// Internal trait for updating to new version of app-state/BundledServer
// in a way that doesn't care about the type of the ServerSetup/ExternalWorld callbacks
trait UpdateServerFn:
    Send
    + FnMut(
        SyncAction,
        mpsc::Sender<()>,
    ) -> Pin<Box<dyn Send + Future<Output = anyhow::Result<Option<Sha256>>>>>
{
}

impl<F> UpdateServerFn for F where
    F: Send
        + FnMut(
            SyncAction,
            mpsc::Sender<()>,
        ) -> Pin<Box<dyn Send + Future<Output = anyhow::Result<Option<Sha256>>>>>
{
}

#[derive(PartialEq, Eq)]
enum SyncAction {
    ReloadCfg,
    Shutdown,
}

/// Bundles 3 (main, monitoring, control) servers together to simplify [`MultiplaneServer::serve`] logic.
struct BundledServer {
    serve_fn: std::sync::Mutex<Box<dyn BundledServeFn>>,
    main_server: Option<Server>,
    monitoring_server: Option<Server>,
    control_server: Option<Server>,
}

impl BundledServer {
    async fn new<AC, AS: AppState>(
        app_state: Arc<AS>,
        server_setup: impl ValidServerSetup<AC, AS>,
        listener_cache: &mut ListenerCacheUpdater<'_, impl ListenFn, 3>,
        read_file: impl ReadFileFn,
        server_cfg: ServerConfig,
        tracker: mpsc::Sender<()>,
    ) -> anyhow::Result<Self> {
        let server_setup = server_setup.to_server_setup();
        let common_data = CommonServerData {
            app_state,
            connected: server_setup.connected,
            connection_failed: server_setup.connection_failed,
            disconnected: server_setup.disconnected,
        };

        if !server_cfg.main.is_enabled() {
            return Err(MainPlaneDisabled.into());
        }
        let main_tls_port = Self::tls_port(&server_cfg.main);
        let (main_server, main_http_listener, main_https_listener) = Self::server_and_listeners(
            server_cfg.main,
            listener_cache,
            read_file.clone(),
            tracker.clone(),
        )
        .await?;
        let monitoring_tls_port = Self::tls_port(&server_cfg.monitoring);
        let (monitoring_server, monitoring_http_listener, monitoring_https_listener) =
            Self::server_and_listeners(
                server_cfg.monitoring,
                listener_cache,
                read_file.clone(),
                tracker.clone(),
            )
            .await?;
        let control_tls_port = Self::tls_port(&server_cfg.control);
        let (control_server, control_http_listener, control_https_listener) =
            Self::server_and_listeners(server_cfg.control, listener_cache, read_file, tracker)
                .await?;

        let respond_to_main = server_setup.respond;
        let respond_to_monitoring = server_setup.respond_to_monitoring;
        let respond_to_control = server_setup.respond_to_control;
        let serve_fn: Box<dyn BundledServeFn> = Box::new(move |this| {
            let common_data = common_data.clone();
            let respond_to_main = respond_to_main.clone();
            let main_http_listener = main_http_listener.clone();
            let main_https_listener = main_https_listener.clone();
            let respond_to_monitoring = respond_to_monitoring.clone();
            let monitoring_http_listener = monitoring_http_listener.clone();
            let monitoring_https_listener = monitoring_https_listener.clone();
            let respond_to_control = respond_to_control.clone();
            let control_http_listener = control_http_listener.clone();
            let control_https_listener = control_https_listener.clone();

            Box::pin(async move {
                let serve_main_http = Self::serve_internal(
                    &common_data,
                    main_http_listener,
                    Self::respond_or_redirect(&respond_to_main, main_tls_port),
                    &this.main_server,
                );
                let serve_main_https = Self::serve_internal(
                    &common_data,
                    main_https_listener,
                    respond_to_main,
                    &this.main_server,
                )
                .instrument(info_span!("tls"));
                let serve_monitoring_http = Self::serve_internal(
                    &common_data,
                    monitoring_http_listener,
                    Self::respond_or_redirect(&respond_to_monitoring, monitoring_tls_port),
                    &this.monitoring_server,
                )
                .instrument(info_span!("monitoring-plane"));
                let serve_monitoring_https = Self::serve_internal(
                    &common_data,
                    monitoring_https_listener,
                    respond_to_monitoring,
                    &this.monitoring_server,
                )
                .instrument(info_span!("monitoring-plane-tls"));
                let serve_control_http = Self::serve_internal(
                    &common_data,
                    control_http_listener,
                    Self::respond_or_redirect(&respond_to_control, control_tls_port),
                    &this.control_server,
                )
                .instrument(info_span!("control-plane"));
                let serve_control_https = Self::serve_internal(
                    &common_data,
                    control_https_listener,
                    respond_to_control,
                    &this.control_server,
                )
                .instrument(info_span!("control-plane-tls"));
                tokio::join!(
                    serve_main_http,
                    serve_main_https,
                    serve_monitoring_http,
                    serve_monitoring_https,
                    serve_control_http,
                    serve_control_https
                );
            })
        });
        let serve_fn = std::sync::Mutex::new(serve_fn);

        Ok(Self {
            serve_fn,
            main_server,
            monitoring_server,
            control_server,
        })
    }

    async fn serve(&self) {
        let fut = (self.serve_fn.lock().unwrap())(self); // serve_fn gets dropped here
        fut.await;
    }

    async fn graceful_shutdown(&self) {
        *self.serve_fn.lock().unwrap() = Self::noop_serve_fn();

        async fn maybe_shutdown(server: &Option<crate::Server>) {
            if let Some(server) = server {
                server.graceful_shutdown().await
            }
        }

        tokio::join!(
            maybe_shutdown(&self.main_server),
            maybe_shutdown(&self.monitoring_server),
            maybe_shutdown(&self.control_server)
        );
    }

    async fn server_and_listeners<Listen: ListenFn>(
        plane_cfg: PlaneConfig,
        listener_cache: &mut ListenerCacheUpdater<'_, Listen, 3>,
        read_file: impl ReadFileFn,
        tracker: mpsc::Sender<()>,
    ) -> anyhow::Result<(
        Option<crate::Server>,
        Option<impl Listener>,
        Option<impl Listener>,
    )> {
        let max_connections = usize::try_from(plane_cfg.max_connections).unwrap_or(usize::MAX);
        let http_listener = match plane_cfg.address {
            Some(addr) => {
                let listener = listener_cache.listen(addr).await?;
                Some(bundle_raii_with_listener(tracker.clone(), listener))
            }
            None => None,
        };

        let https_listener = match plane_cfg.tls_config {
            Some(tls_config) => {
                let listener = listener_cache.listen(tls_config.tls_address).await?;
                let tls_listener = terminate_tls_to_listener(
                    read_file,
                    &tls_config.tls_certificate,
                    &tls_config.tls_private_key,
                    listener,
                )
                .await?;
                Some(bundle_raii_with_listener(tracker, tls_listener))
            }
            None => None,
        };

        let server = (http_listener.is_some() || https_listener.is_some())
            .then_some(crate::Server::new(max_connections));
        Ok((server, http_listener, https_listener))
    }

    async fn serve_internal<
        S: AppState,
        CS: ConnectionState,
        Connected: ConnectedFn<ConnectionState = CS>,
        ConnectionFailed: ConnectionFailedFn,
        Disconnected: DisconnectedFn<CS>,
        L: Listener,
        Respond: ResponseFn<S>,
    >(
        common_data: &CommonServerData<Arc<S>, Connected, ConnectionFailed, Disconnected>,
        listener: Option<L>,
        respond: Respond,
        server: &Option<crate::Server>,
    ) {
        if let (Some(server), Some(listener)) = (server, listener) {
            let app_state = common_data.app_state.clone();
            server
                .with_callbacks()
                .respond(move |request, peer| {
                    let app_state = app_state.clone();
                    let respond = respond.clone();
                    async move { respond(app_state, peer, request).await }
                })
                .connected(common_data.connected.clone())
                .failed(common_data.connection_failed.clone())
                .disconnected(common_data.disconnected.clone())
                .serve(listener())
                .await;
        }
    }

    fn tls_port<T>(plane_cfg: &PlaneConfig<T>) -> Option<u16> {
        plane_cfg
            .tls_config
            .as_ref()
            .map(|cfg| cfg.tls_address.port())
    }

    fn respond_or_redirect<AS: AppState>(
        respond: &impl ResponseFn<AS>,
        tls_port: Option<u16>,
    ) -> impl ResponseFn<AS> {
        either_response_fn(match tls_port {
            None => Either::Left(respond.clone()),
            Some(port) => Either::Right(redirect_to_https(port)),
        })
    }

    fn noop_serve_fn() -> Box<dyn BundledServeFn> {
        Box::new(|_| Box::pin(async {}))
    }
}

impl Default for BundledServer {
    fn default() -> Self {
        Self {
            serve_fn: std::sync::Mutex::new(Self::noop_serve_fn()),
            main_server: None,
            monitoring_server: None,
            control_server: None,
        }
    }
}

// These parameters tend to be grouped together when used by BundledServer.
// Admittedly, there's no realy semantic meaning to this struct... :(
#[derive(Clone)]
struct CommonServerData<ArcS, Connected, ConnectionFailed, Disconnected> {
    app_state: ArcS,
    connected: Connected,
    connection_failed: ConnectionFailed,
    disconnected: Disconnected,
}

// Internal trait for type-erased BundledServer::serve() method
// in a way that doesn't care about the type of the ServerSetup callbacks, etc
trait BundledServeFn:
    Send + Sync + Fn(&'_ BundledServer) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>
{
}

impl<F> BundledServeFn for F where
    F: Send + Sync + Fn(&'_ BundledServer) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>
{
}

// Ensures that if two successive versions of the MultiplaneServer use the same port,
// the new version re-uses the existing listener, preventing a port conflict with itself.
struct ListenerCacheUpdater<'a, L: ListenFn, const N: usize = 3> {
    listen: L,
    old: &'a mut SmallVec<[(SocketAddr, L::Listener); N]>,
    new: SmallVec<[(SocketAddr, L::Listener); N]>,
}

impl<'a, L: ListenFn, const N: usize> ListenerCacheUpdater<'a, L, N> {
    fn new(listen: L, cached_listeners: &'a mut SmallVec<[(SocketAddr, L::Listener); N]>) -> Self {
        Self {
            listen,
            old: cached_listeners,
            new: Default::default(),
        }
    }

    async fn listen(&mut self, addr: SocketAddr) -> std::io::Result<L::Listener> {
        if let Some((_, l)) = self.new.iter().find(|(a, _)| *a == addr) {
            return Ok(l.clone());
        }

        let (addr, listener) = match self.old.iter().find(|(a, _)| *a == addr) {
            Some(pair) => pair.clone(),
            None => (addr, self.listen.clone()(addr).await?),
        };
        self.new.push((addr, listener.clone()));
        Ok(listener)
    }

    fn update(self) {
        *self.old = self.new;
    }
}

// Adapts a Listener, storing an arbitrary `raii` type in every stream of connections it produces.
// This is used to attach RAII guards to the streams of connections to detect whether the socket is still in use.
// Note: We bundle trackers with listeners instead of minhttp::Servers, because we want to detect when the servers
// stop using the listener (at the start of a graceful shutdown), NOT when the server has completely shutdown.
fn bundle_raii_with_listener(
    raii: impl Clone + Send + Sync + 'static,
    listener: impl Listener,
) -> impl Listener {
    move || {
        listener().inspect(move |_| {
            let _raii = &raii;
        })
    }
}

// Unfortunately, these two structs needs to be kept in sync with minhttp::mpserver::cli

/// Connection-related server configuration
///
/// This represents general server configuration, such as addresses to listen on,
/// connection limits, etc. If `T` is specified, it represents app-specific
/// configuration, and is treated as part of the `main` config.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerConfig<T = ()> {
    /// Configuration for the main service
    pub main: PlaneConfig<T>,

    /// Configuration for the monitoring plane
    #[serde(default)]
    pub monitoring: PlaneConfig,

    /// Configuration for the control plane
    #[serde(default)]
    pub control: PlaneConfig,
}

/// Per-plane (main, monitoring, control) configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlaneConfig<T = ()> {
    /// Address to listen on for HTTP.
    pub address: Option<SocketAddr>,

    /// Tls configuation specific to a plane.
    #[serde(flatten)]
    #[serde(deserialize_with = "TlsConfig::deserialize_option")]
    pub tls_config: Option<TlsConfig>,

    /// Maximum simultaneous connections that may be accepted before the server returns 503.
    #[serde(default = "PlaneConfig::default_max_connections")]
    pub max_connections: u32,

    /// Custom application data.
    #[serde(flatten)]
    pub custom: T,
}

impl<T> ServerConfig<T> {
    fn clone_without_custom(&self) -> ServerConfig {
        ServerConfig {
            main: PlaneConfig {
                address: self.main.address,
                tls_config: self.main.tls_config.clone(),
                max_connections: self.main.max_connections,
                custom: (),
            },
            monitoring: self.monitoring.clone(),
            control: self.control.clone(),
        }
    }
}

impl<T: RelativeConfig> RelativeConfig for ServerConfig<T> {
    fn relative_to(self, base: impl AsRef<Path>) -> Self {
        ServerConfig {
            main: self.main.relative_to(&base),
            monitoring: self.monitoring.relative_to(&base),
            control: self.control.relative_to(&base),
        }
    }
}

impl PlaneConfig {
    pub const DEFAULT_MAX_CONNECTIONS: u32 = 1024;

    pub fn default_max_connections() -> u32 {
        1024
    }
}

impl<T> PlaneConfig<T> {
    /// Returns if this plane is configured to listen on any ports.
    pub fn is_enabled(&self) -> bool {
        self.address.is_some() || self.tls_config.is_some()
    }
}

impl<T: RelativeConfig> RelativeConfig for PlaneConfig<T> {
    fn relative_to(self, base: impl AsRef<Path>) -> Self {
        PlaneConfig {
            address: self.address,
            tls_config: self.tls_config.map(|cfg| cfg.relative_to(&base)),
            max_connections: self.max_connections,
            custom: self.custom.relative_to(&base),
        }
    }
}

/// Represents the outside environment the server can be hooked up to.
///
/// This allows tests to e.g. hook up several servers together using a purely in-memory network.
/// There's not yet support for specifying the flow of time.
#[derive(Clone)]
pub struct ExternalWorld<Listen, LoadCfg, ReadFile> {
    /// Callback determining how to listen on ports; must be a [`ListenFn`].
    pub listen: Listen,
    /// Callback determining how configuration files are loaded; must be a [`LoadConfigFn`](super::traits::LoadConfigFn).
    pub load_cfg: LoadCfg,
    /// Callback determining how to read small files; must be a [`ReadFileFn`](super::traits::ReadFileFn).
    ///
    /// NOTE: Not yet used by [`load_cfg`](Self::load_cfg).
    pub read_file: ReadFile,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;

    use hyper::StatusCode;

    use crate::mpserver::common::{read_no_disk, stub_cfg};
    use crate::response::text;
    use crate::test::{send_request, FakeNetwork};

    fn minimal_control_plane<T>(server: &Weak<MultiplaneServer>) -> impl ResponseFn<T> {
        let server = server.clone();
        move |_state, _addr, req| async move {
            let server = Weak::upgrade(&server).unwrap();
            match req.uri().path() {
                "/reload" => server.reload_cfg().await.unwrap(),
                "/shutdown" => server.graceful_shutdown().await,
                _ => return text(StatusCode::NOT_FOUND, "not found"),
            }
            text(StatusCode::OK, "done")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn smoke_test() {
        let network = Arc::new(FakeNetwork::default());
        let server_addr = "192.0.2.2:80".parse().unwrap();

        let cfg = Arc::new(std::sync::Mutex::new(ServerConfig {
            main: PlaneConfig {
                address: Some(server_addr),
                tls_config: None,
                max_connections: 4,
                custom: "Hello world!",
            },
            monitoring: PlaneConfig::default(),
            control: PlaneConfig::default(),
        }));

        let cfg2 = cfg.clone();
        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || cfg2.lock().unwrap().clone()),
            read_file: read_no_disk,
        };

        let server = MultiplaneServer::builder()
            .with_reconfigure(|conf, _prev| async move {
                Ok::<_, Infallible>(Arc::new(conf.main.custom))
            })
            .with_response(|state, _addr, _req| async { text(StatusCode::OK, state) })
            .build_with_external_world(external_world);

        assert!(network.open_ports().is_empty());
        server.reload_cfg().await.unwrap();
        assert_eq!(network.open_ports(), [server_addr].into());

        tokio::join!(server.serve(), async {
            let conn = network.connect(server_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(http_res.ends_with("Hello world!"));

            cfg.lock().unwrap().main.custom = "Second hello!";
            server.reload_cfg().await.unwrap();
            assert_eq!(network.open_ports(), [server_addr].into());

            let conn = network.connect(server_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(http_res.ends_with("Second hello!"));

            server.graceful_shutdown().await;
            assert!(network.open_ports().is_empty());
        });
    }

    // This is primarily about ensuring the MultiplaneServer is implemented in such a way that
    // it won't deadlock if reloaded/shutdown within a response handler.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn basic_control_plane_functionality() {
        let network = Arc::new(FakeNetwork::default());
        let server_addr = "192.0.2.2:80".parse().unwrap();
        let control_addr = "198.51.100.2:80".parse().unwrap();

        let cfg = Arc::new(std::sync::Mutex::new(ServerConfig {
            main: PlaneConfig {
                address: Some(server_addr),
                tls_config: None,
                max_connections: 4,
                custom: "Hello world!",
            },
            monitoring: PlaneConfig::default(),
            control: PlaneConfig {
                address: Some(control_addr),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
        }));

        let cfg2 = cfg.clone();
        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || cfg2.lock().unwrap().clone()),
            read_file: read_no_disk,
        };

        let server = Arc::new_cyclic(|server| {
            MultiplaneServer::builder()
                .with_reconfigure(|conf, _prev| async move {
                    Ok::<_, Infallible>(Arc::new(conf.main.custom))
                })
                .with_response(|state, _addr, _req| async { text(StatusCode::OK, state) })
                .with_response_to_control(minimal_control_plane(server))
                .build_with_external_world(external_world)
        });

        assert!(network.open_ports().is_empty());
        server.reload_cfg().await.unwrap();
        assert_eq!(network.open_ports(), [server_addr, control_addr].into());

        tokio::join!(server.serve(), async {
            let conn = network.connect(server_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(http_res.ends_with("Hello world!"));

            cfg.lock().unwrap().main.custom = "Second hello!";
            let new_control_addr = "198.51.100.3:80".parse().unwrap();
            cfg.lock().unwrap().control.address = Some(new_control_addr);

            let conn = network.connect(control_addr).await.unwrap();
            let http_res = send_request(conn, "POST /reload HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert_eq!(network.open_ports(), [server_addr, new_control_addr].into());

            let conn = network.connect(server_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(http_res.ends_with("Second hello!"));

            let conn = network.connect(new_control_addr).await.unwrap();
            let http_res = send_request(conn, "POST /shutdown HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));

            assert!(network.open_ports().is_empty());
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn client_addresses_are_passed_correctly() {
        let network = Arc::new(FakeNetwork::default());
        let server_addr = "192.0.2.2:80".parse().unwrap();

        let cfg = ServerConfig {
            main: PlaneConfig {
                address: Some(server_addr),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
            monitoring: PlaneConfig::default(),
            control: PlaneConfig::default(),
        };
        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || cfg.clone()),
            read_file: read_no_disk,
        };

        let server = MultiplaneServer::builder()
            .with_reconfigure(|conf, _prev| async move { Ok::<_, Infallible>(Arc::new(conf)) })
            .with_response(
                |_state, addr, _req| async move { text(StatusCode::OK, addr.to_string()) },
            )
            .build_with_external_world(external_world);

        server.reload_cfg().await.unwrap();

        tokio::join!(server.serve(), async {
            let client_addr = "203.0.113.2:12345".parse().unwrap();
            let conn = network
                .connect_from(server_addr, client_addr, 4096)
                .await
                .unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\n203.0.113.2:12345"));

            let client_addr = "192.0.113.42:1122".parse().unwrap();
            let conn = network
                .connect_from(server_addr, client_addr, 4096)
                .await
                .unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\n192.0.113.42:1122"));

            server.graceful_shutdown().await;
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn pathological_listening() {
        let network = Arc::new(FakeNetwork::default());
        let addr1 = "192.0.2.2:80".parse().unwrap();
        let addr2 = "198.51.100.2:80".parse().unwrap();
        let addr3 = "203.0.113.2:80".parse().unwrap();
        let all_addrs = [addr1, addr2, addr3];

        let cfg = Arc::new(std::sync::Mutex::new(ServerConfig {
            main: PlaneConfig {
                address: Some(addr1),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
            monitoring: PlaneConfig {
                address: Some(addr2),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
            control: PlaneConfig {
                address: Some(addr3),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
        }));

        let cfg2 = cfg.clone();
        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || cfg2.lock().unwrap().clone()),
            read_file: read_no_disk,
        };

        let server = Arc::new_cyclic(|server| {
            MultiplaneServer::builder()
                .with_reconfigure(|conf, _prev| async move { Ok::<_, Infallible>(Arc::new(conf)) })
                .with_response(|_state, _addr, _req| async { text(StatusCode::OK, "main") })
                .with_response_to_monitoring(|_state, _addr, _req| async {
                    text(StatusCode::OK, "monitoring")
                })
                .with_response_to_control(minimal_control_plane(server))
                .build_with_external_world(external_world)
        });

        assert!(network.open_ports().is_empty());
        server.reload_cfg().await.unwrap();
        assert_eq!(network.open_ports(), all_addrs.into());

        tokio::join!(server.serve(), async {
            let conn = network.connect(addr1).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nmain"));

            let conn = network.connect(addr2).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nmonitoring"));

            *cfg.lock().unwrap() = ServerConfig {
                main: PlaneConfig {
                    address: Some(addr2),
                    tls_config: None,
                    max_connections: 4,
                    custom: (),
                },
                monitoring: PlaneConfig {
                    address: Some(addr3),
                    tls_config: None,
                    max_connections: 4,
                    custom: (),
                },
                control: PlaneConfig {
                    address: Some(addr1),
                    tls_config: None,
                    max_connections: 4,
                    custom: (),
                },
            };

            assert_eq!(network.open_ports(), all_addrs.into());
            let conn = network.connect(addr3).await.unwrap();
            let http_res = send_request(conn, "POST /reload HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert_eq!(network.open_ports(), all_addrs.into());

            let conn = network.connect(addr2).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nmain"));

            let conn = network.connect(addr3).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nmonitoring"));

            *cfg.lock().unwrap() = ServerConfig {
                main: PlaneConfig {
                    address: Some(addr1),
                    tls_config: None,
                    max_connections: 4,
                    custom: (),
                },
                monitoring: PlaneConfig {
                    address: Some(addr2),
                    tls_config: None,
                    max_connections: 4,
                    custom: (),
                },
                control: PlaneConfig {
                    address: Some(addr3),
                    tls_config: None,
                    max_connections: 4,
                    custom: (),
                },
            };

            assert_eq!(network.open_ports(), all_addrs.into());
            let conn = network.connect(addr1).await.unwrap();
            let http_res = send_request(conn, "POST /reload HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert_eq!(network.open_ports(), all_addrs.into());

            let conn = network.connect(addr1).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nmain"));

            let conn = network.connect(addr2).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nmonitoring"));

            assert_eq!(network.open_ports(), all_addrs.into());
            let conn = network.connect(addr3).await.unwrap();
            let http_res = send_request(conn, "POST /shutdown HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            assert!(http_res.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(network.open_ports().is_empty());
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn regression_triple_reload() {
        let network = Arc::new(FakeNetwork::default());
        let server_addr = "192.0.2.2:80".parse().unwrap();

        let cfg = ServerConfig {
            main: PlaneConfig {
                address: Some(server_addr),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
            monitoring: PlaneConfig::default(),
            control: PlaneConfig::default(),
        };
        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || cfg.clone()),
            read_file: read_no_disk,
        };

        let server = MultiplaneServer::builder()
            .with_reconfigure(|conf, _prev| async move { Ok::<_, Infallible>(Arc::new(conf)) })
            .with_response(|_state, _addr, _req| async move { text(StatusCode::OK, "It works!") })
            .build_with_external_world(external_world);

        server.reload_cfg().await.unwrap();
        server.reload_cfg().await.unwrap();
        server.reload_cfg().await.unwrap();

        tokio::join!(server.serve(), async {
            let conn = network.connect(server_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nIt works!"));

            server.graceful_shutdown().await;
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn can_disable_and_enable_optional_services() {
        let network = Arc::new(FakeNetwork::default());
        let server_addr = "192.0.2.2:80".parse().unwrap();
        let monitoring_addr = "198.51.100.2:80".parse().unwrap();
        let control_addr = "198.51.100.3:80".parse().unwrap();

        let cfg = Arc::new(std::sync::Mutex::new(ServerConfig {
            main: PlaneConfig {
                address: Some(server_addr),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
            monitoring: PlaneConfig {
                address: Some(monitoring_addr),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
            control: PlaneConfig {
                address: Some(control_addr),
                tls_config: None,
                max_connections: 4,
                custom: (),
            },
        }));

        let cfg2 = cfg.clone();
        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || cfg2.lock().unwrap().clone()),
            read_file: read_no_disk,
        };

        let server = MultiplaneServer::builder()
            .with_reconfigure(|conf, _prev| async move { Ok::<_, Infallible>(Arc::new(conf)) })
            .with_response(|_state, _addr, _req| async { text(StatusCode::OK, "main") })
            .with_response_to_monitoring(|_state, _addr, _req| async {
                text(StatusCode::OK, "monitoring")
            })
            .with_response_to_control(|_state, _addr, _req| async {
                text(StatusCode::OK, "control")
            })
            .build_with_external_world(external_world);

        assert!(network.open_ports().is_empty());
        server.reload_cfg().await.unwrap();
        assert_eq!(
            network.open_ports(),
            [server_addr, monitoring_addr, control_addr].into()
        );

        tokio::join!(server.serve(), async {
            let conn = network.connect(monitoring_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nmonitoring"));

            let conn = network.connect(control_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\ncontrol"));

            cfg.lock().unwrap().monitoring = PlaneConfig::default();
            cfg.lock().unwrap().control = PlaneConfig::default();
            server.reload_cfg().await.unwrap();

            assert_eq!(network.open_ports(), [server_addr].into());

            cfg.lock().unwrap().monitoring = PlaneConfig {
                address: Some(monitoring_addr),
                tls_config: None,
                max_connections: 4,
                custom: (),
            };
            cfg.lock().unwrap().control = PlaneConfig {
                address: Some(control_addr),
                tls_config: None,
                max_connections: 4,
                custom: (),
            };
            server.reload_cfg().await.unwrap();

            assert_eq!(
                network.open_ports(),
                [server_addr, monitoring_addr, control_addr].into()
            );

            let conn = network.connect(monitoring_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\nmonitoring"));

            let conn = network.connect(control_addr).await.unwrap();
            let http_res = send_request(conn, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
            assert!(http_res.ends_with("\r\ncontrol"));

            server.graceful_shutdown().await;

            assert!(network.open_ports().is_empty());
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn main_plane_is_required() {
        let network = Arc::new(FakeNetwork::default());

        let cfg = ServerConfig {
            main: PlaneConfig {
                address: None,
                tls_config: None,
                max_connections: 4,
                custom: "Hello world!",
            },
            monitoring: PlaneConfig::default(),
            control: PlaneConfig::default(),
        };

        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || cfg.clone()),
            read_file: read_no_disk,
        };

        let server = MultiplaneServer::builder()
            .with_reconfigure(|conf, _prev| async move {
                Ok::<_, Infallible>(Arc::new(conf.main.custom))
            })
            .with_response(|state, _addr, _req| async { text(StatusCode::OK, state) })
            .build_with_external_world(external_world);

        server.reload_cfg().await.unwrap_err();
    }
}
