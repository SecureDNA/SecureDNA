// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public traits used to simplify functional interfaces.
//!
//! Anything that behaves like an async closure ends up being a bit messy to represent
//! in Rust. This contains traits for async fn types (and anything related/complicated)
//! that show up in the MPServer API, in the hopes of simplifying said API.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Weak};

use futures::Stream;
use hyper::{body::Incoming, Request};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::response::GenericResponse;
use crate::server::ConnectionError;

use super::{ExternalWorld, ServerConfig, ServerSetup};

/// Short-hand for checking that a [`ServerSetup`]'s callbacks are valid and fit together.
pub trait ValidServerSetup<AC, AS> {
    type ConnectionState: ConnectionState;

    fn to_server_setup(
        self,
    ) -> ServerSetup<
        impl ReconfigureFn<AC, AS>,
        impl ResponseFn<AS>,
        impl ResponseFn<AS>,
        impl ResponseFn<AS>,
        impl ConnectedFn<ConnectionState = Self::ConnectionState>,
        impl ConnectionFailedFn,
        impl DisconnectedFn<Self::ConnectionState>,
    >;
}

impl<
        AC: 'static,
        AS: AppState,
        Reconfigure: ReconfigureFn<AC, AS>,
        Respond: ResponseFn<AS>,
        RespondToMonitoring: ResponseFn<AS>,
        RespondToControl: ResponseFn<AS>,
        CS: ConnectionState,
        Connected: ConnectedFn<ConnectionState = CS>,
        ConnectionFailed: ConnectionFailedFn,
        Disconnected: DisconnectedFn<CS>,
    > ValidServerSetup<AC, AS>
    for ServerSetup<
        Reconfigure,
        Respond,
        RespondToMonitoring,
        RespondToControl,
        Connected,
        ConnectionFailed,
        Disconnected,
    >
{
    type ConnectionState = CS;

    fn to_server_setup(
        self,
    ) -> ServerSetup<
        impl ReconfigureFn<AC, AS>,
        impl ResponseFn<AS>,
        impl ResponseFn<AS>,
        impl ResponseFn<AS>,
        impl ConnectedFn<ConnectionState = Self::ConnectionState>,
        impl ConnectionFailedFn,
        impl DisconnectedFn<Self::ConnectionState>,
    > {
        self
    }
}

/// Similar to `async fn(AC, Weak<AS>) -> Result<Arc<AS>, impl Error>`
///
/// [`ReconfigureFn`] is used by [`ServerSetup`] to control how the server interprets new
/// configurations. [`ReconfigureFn`] is passed a new application configuration of type `AC`
/// and a `Weak<AS>` to the previous [`AppState`] (if there is any) and is expected
/// return a new `Arc<AppState>`.
pub trait ReconfigureFn<AC, AS>:
    'static + Clone + Send + FnOnce(ServerConfig<AC>, Weak<AS>) -> Self::Future
{
    type Future: Send + Future<Output = Result<Arc<AS>, Self::Error>>;
    type Error: std::error::Error + Send + Sync + 'static;
}

impl<AC, AS, F, Fut, E> ReconfigureFn<AC, AS> for F
where
    F: 'static + Clone + Send + FnOnce(ServerConfig<AC>, Weak<AS>) -> Fut,
    Fut: Send + Future<Output = Result<Arc<AS>, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    type Future = Fut;
    type Error = E;
}

/// Similar to `async fn(Arc<AS>, SocketAddr, Request<Incoming>) -> GenericResponse`
///
/// [`ResponseFn`] is used by [`ServerSetup`] to control how the server responds to incoming
/// requests. `AS` should be an [`AppState`].
pub trait ResponseFn<AS>:
    'static + Clone + Send + Sync + FnOnce(Arc<AS>, SocketAddr, Request<Incoming>) -> Self::Future
{
    type Future: Future<Output = GenericResponse> + Send;
}

impl<AS, F, Fut> ResponseFn<AS> for F
where
    F: 'static + Clone + Send + Sync + FnOnce(Arc<AS>, SocketAddr, Request<Incoming>) -> Fut,
    Fut: Future<Output = GenericResponse> + Send,
{
    type Future = Fut;
}

/// Application config containing inert info to be interepreted as [`AppState`].
///
/// This is produced by [`LoadConfigFn`] (usually from reading and parsing a file),
/// and sent to [`ReconfigureFn`] which produces an [`AppState`] from it.
pub trait AppConfig: 'static + Send {}

impl<T> AppConfig for T where T: 'static + Send {}

/// Per-server, per-revision application state.
///
/// This represents shared server-wide custom app state such as caches, connection pools,
/// config settings, etc. [`AppState`]s are built by [`ReconfigureFn`] whenever the server
/// is reconfigured and passed to [`ResponseFn`]s whenever they handle a request.
///
/// In order to allow servers to be gracefully reconfigured, **multiple [`AppState`]s may
/// be in-use simultaneously**. A [`ResponseFn`] will be passed whichever [`AppState`] was
/// current **when the connection began**.
pub trait AppState: Send + Sync + 'static {}

impl<T> AppState for T where T: Send + Sync + 'static {}

/// Similar to `fn(SocketAddr) -> impl ConnectionState`
///
/// [`ConnectedFn`] is used by [`ServerSetup`] to customize connection state/diagnostics.
/// The [`ConnectedFn`] must return an [`impl ConnectionState`](ConnectionState), which is
/// then kept alive for as long as the connection and passed to a [`DisconnectedFn`] when
/// the connection is terminated.
pub trait ConnectedFn:
    'static + Clone + Send + Sync + FnMut(SocketAddr) -> Self::ConnectionState
{
    type ConnectionState: ConnectionState;
}

impl<F, CS> ConnectedFn for F
where
    F: 'static + Clone + Send + Sync + FnMut(SocketAddr) -> CS,
    CS: ConnectionState,
{
    type ConnectionState = CS;
}

/// Similar to `fn(ConnectionError)`
///
/// [`ConnectionFailedFn`] is used by [`ServerSetup`] to customize connection diagnostics.
/// If an error occurs, the [`ConnectionFailedFn`] will be invoked with a [`ConnectionError`].
pub trait ConnectionFailedFn: Clone + Send + Sync + 'static + FnOnce(ConnectionError) {}

impl<F> ConnectionFailedFn for F where F: Clone + Send + Sync + 'static + FnOnce(ConnectionError) {}

/// Similar to `fn(impl ConnectionState)`
///
/// [`DisconnectedFn`] is used by [`ServerSetup`] to customize connection state/diagnostics.
/// If a connection terminates, the [`DisconnectedFn`] will be invoked with the
/// [`ConnectionState`] produced by [`ConnectedFn`].
pub trait DisconnectedFn<CS: ConnectionState>: Clone + Send + Sync + 'static + FnOnce(CS) {}

impl<CS: ConnectionState, F> DisconnectedFn<CS> for F where
    F: Clone + Send + Sync + 'static + FnOnce(CS)
{
}

/// State passed from [`ConnectedFn`] to [`DisconnectedFn`]
///
/// This represents any kind of custom state that can be created by [`ConnectedFn`], stored with
/// a connection, then passed to [`DisconnectedFn`] when a connection terminates.
/// [`MultiplaneServer`](super::MultiplaneServer)s don't care what this is.
///
/// Currently there is no easy way to access this from a [`ResponseFn`].
pub trait ConnectionState: Send + 'static {}

impl<T> ConnectionState for T where T: Send + 'static {}

/// Short-hand for checking that an [`ExternalWorld`]'s callbacks are valid and fit together.
pub trait ValidExternalWorld<AC> {
    fn to_external_world(self) -> ExternalWorld<impl ListenFn, impl LoadConfigFn<AC>>;
}

impl<AC, Listen: ListenFn, LoadConfig: LoadConfigFn<AC>> ValidExternalWorld<AC>
    for ExternalWorld<Listen, LoadConfig>
{
    fn to_external_world(self) -> ExternalWorld<impl ListenFn, impl LoadConfigFn<AC>> {
        self
    }
}

/// Similar to `async fn(SocketAddr) -> std::io::Result<impl Listener>`
///
/// [`ListenFn`] is used by [`ExternalWorld`] to control how the server listens for incoming
/// connections. This function should listen (or pretend to listen) on the given [`SocketAddr`]
/// and return a [`Listener`] representing the open port.
///
/// [`default_listen_fn`](super::common::default_listen_fn) provides sane behavior if your goal is
/// to listen to the network.
pub trait ListenFn: 'static + Clone + Send + FnOnce(SocketAddr) -> Self::Future {
    type Future: Send + Future<Output = std::io::Result<Self::Listener>>;
    type Listener: Listener;
}

impl<F, Fut, L> ListenFn for F
where
    F: 'static + Clone + Send + FnOnce(SocketAddr) -> Fut,
    Fut: Send + Future<Output = std::io::Result<L>>,
    L: Listener,
{
    type Future = Fut;
    type Listener = L;
}

/// Similar to `fn() -> impl Connections`
///
/// [`Listener`] is returned by [`ListenFn`] and represents an open port; calling it will return
/// an [`impl Connections`](Connections). Note that it's valid to call this any number of times
/// without dropping previous [`Connections`], in much the same way that multiple threads are
/// allowed to share a single [`TcpListener`](tokio::net::TcpListener).
///
/// Why bother with [`Listener`]? Why not just have [`ListenFn`] directly return
/// [`impl Connections`](Connections)? Because multiple workers need to be able to accept
/// connections from the same port in parallel and ad hoc `async`-blocks and [`Stream`]s are
/// unpleasant to make [`Clone`]able. An ideal implementation would make [`Listener`] be a
/// subtrait of [`Clone`] and some kind of `IntoStream` (akin to [`IntoIterator`]), but no such
/// `IntoStream` exists yet, so we instead just make this a `fn() -> impl Connections`.
pub trait Listener: 'static + Clone + Send + Sync + FnOnce() -> Self::Connections {
    type Connections: Connections;
}

impl<F, C> Listener for F
where
    F: 'static + Clone + Send + Sync + FnOnce() -> C,
    C: Connections,
{
    type Connections = C;
}

/// Similar to `Stream<Item = std::io::Result<(impl Connection, SocketAddr)>>`
///
/// This is returned by [`Listener`] to represent a stream of incoming [`Connection`]s.
pub trait Connections:
    Send + Stream<Item = std::io::Result<(Self::Connection, SocketAddr)>>
{
    type Connection: Connection;
}

impl<T, C> Connections for T
where
    T: Send + Stream<Item = std::io::Result<(C, SocketAddr)>>,
    C: Connection,
{
    type Connection = C;
}

/// Abstract connection.
///
/// This is yielded by [`Connections`] and can be anything sufficiently connection-like
/// (such as [`TcpStream`](tokio::net::TcpStream)) to be used by a
/// [`MultiplaneServer`](super::MultiplaneServer). This allows instead using e.g. in-memory
/// connections for testing or using encrypted connections for TLS.
pub trait Connection: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<C> Connection for C where C: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// Similar to `async fn() -> Result<C, impl Error>`
///
/// [`LoadConfigFn<C>`] is used by [`ExternalWorld`] to control where a server gets new
/// configurations from. When called, it should attempt to somehow generate a configuration
/// of type `C`, for example by reading a file.
pub trait LoadConfigFn<C>: 'static + Clone + Send + FnOnce() -> Self::Future {
    type Future: Send + Future<Output = Result<(C, Sha256), Self::Error>>;
    type Error: std::error::Error + Send + Sync + 'static;
}

impl<C, F, Fut, E> LoadConfigFn<C> for F
where
    F: 'static + Clone + Send + FnOnce() -> Fut,
    Fut: Send + Future<Output = Result<(C, Sha256), E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    type Future = Fut;
    type Error = E;
}

/// Allows a config to have its paths updated to be relative to a given directory.
pub trait RelativeConfig: Sized {
    /// Consume self, returning version of config with its paths updated to be relative to `base`
    fn relative_to(self, _base: impl AsRef<Path>) -> Self {
        self
    }
}
