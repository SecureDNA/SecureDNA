// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test utilities for simulated networks

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use crate::mpserver::traits::{ListenFn, Listener};

/// Purely in-memory "network" used for testing
#[derive(Default)]
pub struct FakeNetwork {
    ports: std::sync::Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<(DuplexStream, SocketAddr)>>>,
}

impl FakeNetwork {
    /// Create a new [`FakeNetwork`]
    pub fn new() -> Self {
        Self {
            ports: Default::default(),
        }
    }

    /// Opens a new connection to a port previously opened via [`listen`](Self::listen).
    ///
    /// Uses `203.0.113.254:12345` as the client address and use 4kb connection buffers.
    pub async fn connect(&self, addr: SocketAddr) -> std::io::Result<DuplexStream> {
        let client_addr = "203.0.113.254:12345".parse().unwrap();
        let buffer_size = 4096;
        self.connect_from(addr, client_addr, buffer_size).await
    }

    /// Opens a new connection to a port previously opened via [`listen`](Self::listen).
    ///
    /// `client_addr` is the address the new connection is opened from.
    /// `buffer_size` is passed to [`duplex`](tokio::io::duplex); it's the amount of data that
    /// can be written to each side of the connection without interruption.
    /// Returns a [`DuplexStream`] representing one end of the connection.
    pub async fn connect_from(
        &self,
        addr: SocketAddr,
        client_addr: SocketAddr,
        buffer_size: usize,
    ) -> std::io::Result<DuplexStream> {
        async {
            let mut ports = self.ports.lock().unwrap();
            let connections = ports.get_mut(&addr)?;
            let (client, server) = tokio::io::duplex(buffer_size);
            connections.send((server, client_addr)).ok()?;
            Some(client)
        }
        .await
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
    }

    /// Open a port to listen on.
    ///
    /// Returns a [`Listener`] (a callable that generates a [`Stream`](futures::Stream) of
    /// incoming connections). After returning, the given `addr` may be
    /// [`connect`](Self::connect)ed to.
    pub fn listen(&self, addr: SocketAddr) -> std::io::Result<impl Listener> {
        let mut ports = self.ports.lock().unwrap();
        if let Some(port) = ports.get(&addr) {
            if !port.is_closed() {
                return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse));
            }
        }

        let (tx, rx) = mpsc::unbounded_channel();
        ports.insert(addr, tx);

        let port = Arc::new(tokio::sync::Mutex::new(rx));
        Ok(move || {
            futures::stream::unfold(port.clone(), |port| async {
                let conn_addr = port.lock().await.recv().await;
                conn_addr.map(|conn_addr| (Ok(conn_addr), port))
            })
        })
    }

    /// Open a port to listen on, returning a [`ListenFn`].
    pub fn listen_fn(self: &Arc<Self>) -> impl ListenFn {
        let this = self.clone();
        move |addr| async move { this.listen(addr) }
    }

    /// Return list of [`SocketAddr`]s that are listening for incoming connections.
    pub fn open_ports(&self) -> HashSet<SocketAddr> {
        let ports = self.ports.lock().unwrap();
        ports
            .iter()
            .filter(|(_k, v)| !v.is_closed())
            .map(|(k, _v)| *k)
            .collect()
    }
}

/// Send and receive a string over a connection-like.
///
/// This sends a `request` [`str`] and receives a response [`String`] concurrently so that the
/// size of any connection buffers don't matter.
pub async fn send_request(
    connection: impl AsyncRead + AsyncWrite,
    request: impl AsRef<str>,
) -> std::io::Result<String> {
    let request = request.as_ref().as_bytes();
    let mut response = String::new();
    let (mut r, mut w) = tokio::io::split(connection);
    tokio::try_join!(
        async move {
            w.write_all(request).await?;
            w.shutdown().await
        },
        r.read_to_string(&mut response)
    )?;
    Ok(response)
}
