// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::SocketAddr;

use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tracing::info;

use minhttp::signal::{fast_shutdown_requested, graceful_shutdown_requested};
use minhttp::Server;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let address = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("Listening on {address}");
    let listener = TcpListener::bind(address).await.unwrap();
    let connections = futures::stream::unfold(listener, |listener| async {
        Some((listener.accept().await, listener))
    });

    let max_connections = 2;
    let server = Server::new(max_connections);

    let run = server.serve(connections, respond);

    let graceful_shutdown = async {
        graceful_shutdown_requested().await;
        info!("Graceful shutdown requested...");
        server.graceful_shutdown().await;
    };

    let run_until_gracefully_shutdown = async { tokio::join!(run, graceful_shutdown) };

    tokio::select! {
        _ = run_until_gracefully_shutdown => {}
        _ = fast_shutdown_requested() => info!("Fast shutdown requested..."),
    };
}

async fn respond(
    _request: Request<Incoming>,
    _peer: SocketAddr,
) -> minhttp::response::GenericResponse {
    let msg = "Hello world!\n";
    let body = Full::from(msg).map_err(|_| unreachable!()).boxed();
    let mut response = Response::new(body);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain;charset=UTF-8"),
    );
    response
}
