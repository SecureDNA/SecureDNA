// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::Context;
use futures::FutureExt;
use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, info_span, Instrument};

use certificates::{KeyserverTokenGroup, Manufacturer};
use doprf::active_security::ActiveSecurityKey;
use minhttp::response::{self, ErrResponse, GenericResponse};
use minhttp::server::Server;
use minhttp::signal::{fast_shutdown_requested, graceful_shutdown_requested};
use scep_server_helpers::server::ServerState;
use securedna_versioning::version::get_version;
use shared_types::hash::HashSpec;
use shared_types::http::add_cors_headers;
use shared_types::server_selection::KeyInfo;
use shared_types::server_versions::KeyserverVersion;
use shared_types::{
    metrics::{get_metrics_output, KSMetrics},
    requests::RequestId,
};

use crate::state::{GenerationKeyInfo, KeyserverState};
use crate::Opts;

/// SCEP server version
const SERVER_VERSION: u64 = 1;

pub async fn run(opts: Opts, post_setup_hook: impl Future<Output = ()>) -> anyhow::Result<()> {
    // Avoiding std::thread::available_parallelism because the KS seems to experience too much
    // contention between cores, so using the physical number of cores seems better.
    let num_cores = num_cpus::get_physical();
    let crypto_parallelism_per_server = opts.crypto_parallelism_per_server.unwrap_or(num_cores);
    let parallelism_per_request = opts
        .crypto_parallelism_per_request
        .unwrap_or(num_cores)
        .min(crypto_parallelism_per_server);
    info!(
        "Parallelism: per-request={} per-server={} physical-cores={} logical-cores={}",
        parallelism_per_request,
        crypto_parallelism_per_server,
        num_cores,
        num_cpus::get(),
    );

    if opts.active_security_key.len() != opts.keyholders_required as usize {
        anyhow::bail!(
            "Invalid number of commitments supplied for the active security key: expected {}, but found {}",
            opts.keyholders_required,
            opts.active_security_key.len()
        );
    }
    let active_security_key = ActiveSecurityKey::from_commitments(opts.active_security_key);

    let manufacturer_roots =
        scep_server_helpers::certs::read_certificates::<Manufacturer>(opts.manufacturer_roots)
            .context("reading manufacturer root certs")?
            .into_iter()
            .map(|c| *c.public_key())
            .collect::<Vec<_>>();

    let token_bundle =
        scep_server_helpers::certs::read_tokenbundle::<KeyserverTokenGroup>(opts.token_file)
            .context("reading keyserver token bundle")?;

    let passphrase = fs::read_to_string(&opts.keypair_passphrase_file)
        .context("reading keyserver keypair passphrase file")?;

    let keypair = scep_server_helpers::certs::read_keypair(opts.keypair_file, passphrase.trim())
        .context("reading keyserver keypair")?;

    let heavy_requests = Arc::new(Semaphore::new(opts.max_heavy_clients));
    let processing_chunks = Arc::new(Semaphore::new(crypto_parallelism_per_server));

    let metrics = opts.monitoring_plane_port.map(|_| {
        let m = KSMetrics::default();
        m.max_clients.set(opts.max_clients as i64);
        Arc::new(m)
    });

    let generations_key_info = {
        let mut h = HashMap::new();
        h.insert(
            0,
            KeyInfo {
                quorum: opts.keyholders_required,
                active_security_key,
            },
        );
        GenerationKeyInfo(h)
    };

    let ks_state = Arc::new(KeyserverState {
        heavy_requests,
        keyserver_id: opts.id,
        keyshare: opts.keyshare,
        generations_key_info,
        metrics: metrics.clone(),
        processing_chunks,
        parallelism_per_request,
        scep: ServerState {
            clients: Default::default(),
            json_size_limit: opts.scep_json_size_limit,
            manufacturer_roots,
            token_bundle,
            keypair,
            allow_insecure_cookie: opts.allow_insecure_cookie,
        },
    });

    let server = Server::new(opts.max_clients);
    // Note: Separate server so regular connections don't count against the monitoring plane limit.
    let monitoring_plane_server = Server::new(opts.max_monitoring_plane_clients);

    let address = SocketAddr::from(([0, 0, 0, 0], opts.port));
    info!("Listening on {address}");
    let listener = TcpListener::bind(address).await.unwrap();
    let connections = futures::stream::unfold(listener, |listener| async {
        Some((listener.accept().await, listener))
    });

    let metrics2 = metrics.clone();
    let run = server
        .with_callbacks()
        .respond(move |request, peer| {
            let ks_state = ks_state.clone();
            let request_id = RequestId::from(request.headers());
            async move { respond(ks_state.clone(), &request_id, peer, request).await }
        })
        .connected(|_| metrics.as_ref().map(|m| m.connected_clients()))
        .failed(move |_| {
            if let Some(m) = metrics2 {
                m.bad_requests.inc();
            }
        })
        .serve(connections);

    let run_monitoring_plane = if let Some(port) = opts.monitoring_plane_port {
        let address = SocketAddr::from(([0, 0, 0, 0], port));
        info!("Listening on {address} for monitoring plane");
        let listener = TcpListener::bind(address).await.unwrap();
        let connections = futures::stream::unfold(listener, |listener| async {
            Some((listener.accept().await, listener))
        });

        let run = monitoring_plane_server
            .with_callbacks()
            .respond(respond_to_monitoring_plane)
            .serve(connections)
            .instrument(info_span!("monitoring-plane"));

        run.left_future()
    } else {
        async {}.right_future()
    };

    let graceful_shutdown = async {
        graceful_shutdown_requested().await;
        info!("Graceful shutdown requested...");
        tokio::join!(
            server.graceful_shutdown(),
            monitoring_plane_server.graceful_shutdown()
        );
    };

    // Note: Monitoring plane comes first to prioritize handling its traffic.
    let run_until_gracefully_shutdown =
        async { tokio::join!(run_monitoring_plane, run, graceful_shutdown) };
    post_setup_hook.await;
    tokio::select! {
        biased;
        _ = fast_shutdown_requested() => info!("Fast shutdown requested..."),
        _ = run_until_gracefully_shutdown => {}
    };

    Ok(())
}

async fn respond(
    ks_state: Arc<KeyserverState>,
    request_id: &RequestId,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> GenericResponse {
    let method = request.method().clone();
    let headers = request.headers().clone();
    let mut response = match request.uri().path() {
        "/qualification" => {
            handle_post(
                &method,
                handle_err(
                    &ks_state.metrics,
                    crate::qualification::qualification(&ks_state, request),
                ),
            )
            .await
        }
        "/version" => handle_get(&method, version()).await,
        scep::OPEN_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &ks_state.metrics,
                    request_id,
                    peer,
                    scep_endpoint_open(&ks_state, request),
                ),
            )
            .await
        }
        scep::AUTHENTICATE_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &ks_state.metrics,
                    request_id,
                    peer,
                    scep_endpoint_authenticate(&ks_state, request),
                ),
            )
            .await
        }
        scep::KEYSERVE_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &ks_state.metrics,
                    request_id,
                    peer,
                    crate::keyserve::scep_endpoint_keyserve(request_id, &ks_state, request),
                ),
            )
            .await
        }
        _ => response::not_found(),
    };
    add_cors_headers(&headers, response.headers_mut());
    response
}

async fn handle_get(
    method: &Method,
    future: impl Future<Output = GenericResponse>,
) -> GenericResponse {
    match *method {
        Method::GET => future.await,
        Method::OPTIONS => response::empty(),
        _ => response::not_found(),
    }
}

async fn handle_post(
    method: &Method,
    future: impl Future<Output = GenericResponse>,
) -> GenericResponse {
    match *method {
        Method::POST => future.await,
        Method::OPTIONS => response::empty(),
        _ => response::not_found(),
    }
}

async fn handle_err(
    metrics: &Option<Arc<KSMetrics>>,
    future: impl Future<Output = Result<GenericResponse, ErrResponse>>,
) -> GenericResponse {
    let result_response = future.await;
    match (result_response, &metrics) {
        (Err(ErrResponse(r)), Some(metrics)) => {
            metrics.bad_requests.inc();
            r
        }
        (Ok(r) | Err(ErrResponse(r)), _) => r,
    }
}

async fn handle_scep_err<F, E>(
    metrics: &Option<Arc<KSMetrics>>,
    request_id: &RequestId,
    peer: SocketAddr,
    future: F,
) -> GenericResponse
where
    F: Future<Output = Result<GenericResponse, scep::error::ScepError<E>>>,
    E: std::error::Error,
{
    let result_response = future.await;
    match result_response {
        Ok(r) => r,
        Err(e) => {
            let ErrResponse(r) =
                scep_server_helpers::log_and_convert_scep_error_to_response(&e, request_id, peer);
            if let Some(metrics) = metrics {
                metrics.bad_requests.inc();
            }
            r
        }
    }
}

async fn version() -> GenericResponse {
    let response = KeyserverVersion {
        server_version: get_version(),
    };
    // this serialization can't fail
    let json = serde_json::to_string(&response).unwrap();
    response::json(StatusCode::OK, json)
}

async fn scep_endpoint_open(
    server_state: &KeyserverState,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerPrevalidation>> {
    scep_server_helpers::server::scep_endpoint_open(
        &server_state.scep,
        SERVER_VERSION,
        &HashSpec {
            max_expansions_per_window: NonZeroUsize::MIN,
            htdv: vec![],
        },
        |_| async { None },
        |_, _| async {},
        request,
    )
    .await
}

async fn scep_endpoint_authenticate(
    server_state: &KeyserverState,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerAuthentication>> {
    scep_server_helpers::server::scep_endpoint_authenticate(
        &server_state.scep,
        SERVER_VERSION,
        |_| async { Ok(0) },
        |_, _| async {},
        request,
    )
    .await
}

async fn respond_to_monitoring_plane(
    request: Request<Incoming>,
    _peer: SocketAddr,
) -> GenericResponse {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => query_server_metrics(),
        _ => response::text(StatusCode::NOT_FOUND, "404 not found"),
    }
}

fn query_server_metrics() -> GenericResponse {
    response::text(StatusCode::OK, get_metrics_output())
}
