// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Weak};

use anyhow::Context;
use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};
use tokio::sync::Semaphore;
use tracing::{error, info};

use certificates::{Issued, KeyserverTokenGroup, Manufacturer};
use doprf::active_security::ActiveSecurityKey;
use minhttp::error::ErrWrapper;
use minhttp::mpserver::{traits::ValidServerSetup, MultiplaneServer, ServerConfig};
use minhttp::response::{self, ErrResponse, GenericResponse};
use scep_server_helpers::server::ServerState;
use securedna_versioning::version::get_version;
use shared_types::hash::HashSpec;
use shared_types::http::add_cors_headers;
use shared_types::server_selection::KeyInfo;
use shared_types::server_versions::KeyserverVersion;
use shared_types::{
    metrics::{get_metrics_output, KeyserverMetrics},
    requests::RequestId,
};

use crate::state::{GenerationKeyInfo, KeyserverState};
use crate::{event_store, Config};

/// SCEP server version
const SERVER_VERSION: u64 = 1;

pub fn server_setup() -> impl ValidServerSetup<Config, KeyserverState> {
    MultiplaneServer::builder()
        .with_reconfigure(reconfigure)
        .with_response(respond)
        .with_response_to_monitoring(respond_to_monitoring_plane)
}

async fn reconfigure(
    server_cfg: ServerConfig<Config>,
    prev_state: Weak<KeyserverState>,
) -> Result<Arc<KeyserverState>, ErrWrapper> {
    let app_cfg = server_cfg.main.custom;
    let prev_state = Weak::upgrade(&prev_state);

    // Avoiding std::thread::available_parallelism because the KS seems to experience too much
    // contention between cores, so using the physical number of cores seems better.
    let num_cores = num_cpus::get_physical();
    let crypto_parallelism_per_server = app_cfg.crypto_parallelism_per_server.unwrap_or(num_cores);
    let parallelism_per_request = app_cfg
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

    if app_cfg.active_security_key.len() != app_cfg.keyholders_required as usize {
        return Err(anyhow::anyhow!(
            "Invalid number of commitments supplied for the active security key: expected {}, but found {}",
            app_cfg.keyholders_required,
            app_cfg.active_security_key.len()
        ).into());
    }
    let active_security_key = ActiveSecurityKey::from_commitments(app_cfg.active_security_key);

    let manufacturer_roots =
        scep_server_helpers::certs::read_certificates::<Manufacturer>(app_cfg.manufacturer_roots)
            .context("reading manufacturer root certs")?
            .into_iter()
            .map(|c| *c.public_key())
            .collect::<Vec<_>>();

    let token_bundle =
        scep_server_helpers::certs::read_tokenbundle::<KeyserverTokenGroup>(app_cfg.token_file)
            .context("reading keyserver token bundle")?;

    let passphrase = fs::read_to_string(&app_cfg.keypair_passphrase_file)
        .context("reading keyserver keypair passphrase file")?;

    let keypair = scep_server_helpers::certs::read_keypair(app_cfg.keypair_file, passphrase.trim())
        .context("reading keyserver keypair")?;

    let heavy_requests = Arc::new(Semaphore::new(app_cfg.max_heavy_clients));
    let processing_chunks = Arc::new(Semaphore::new(crypto_parallelism_per_server));

    // Once metrics are enabled, they can't be disabled.
    // (at least, I don't yet know enough about our metrics code to be sure that's sensible)
    let metrics = if let Some(prev_metrics) = prev_state.as_ref().map(|s| &s.metrics) {
        prev_metrics.clone()
    } else if server_cfg.monitoring.is_some() {
        let m = KeyserverMetrics::default();
        m.max_clients.set(server_cfg.main.max_connections as i64);
        Some(Arc::new(m))
    } else {
        None
    };

    let generations_key_info = {
        let mut h = HashMap::new();
        h.insert(
            0,
            KeyInfo {
                quorum: app_cfg.keyholders_required,
                active_security_key,
            },
        );
        GenerationKeyInfo(h)
    };

    let persistence_connection = if let Some(prev_state) = prev_state {
        if app_cfg.event_store_path != prev_state.persistence_path {
            return Err(anyhow::anyhow!(
                "Changes to event_store_path not supported: expected {:?}, but found {:?}",
                prev_state.persistence_path,
                app_cfg.event_store_path,
            )
            .into());
        }
        prev_state.persistence_connection.clone()
    } else {
        crate::event_store::open_db(&app_cfg.event_store_path)
            .await
            .context("opening event_store db")?
    };

    Ok(Arc::new(KeyserverState {
        heavy_requests,
        keyserver_id: app_cfg.id,
        keyshare: app_cfg.keyshare,
        generations_key_info,
        metrics: metrics.clone(),
        processing_chunks,
        parallelism_per_request,
        scep: ServerState {
            clients: Default::default(),
            json_size_limit: app_cfg.scep_json_size_limit,
            manufacturer_roots,
            token_bundle,
            keypair,
            allow_insecure_cookie: app_cfg.allow_insecure_cookie,
        },
        persistence_path: app_cfg.event_store_path,
        persistence_connection,
    }))
}

async fn respond(
    ks_state: Arc<KeyserverState>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> GenericResponse {
    let request_id = &RequestId::from(request.headers());
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
    metrics: &Option<Arc<KeyserverMetrics>>,
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
    metrics: &Option<Arc<KeyserverMetrics>>,
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
        |client_mid| async move {
            match event_store::last_protocol_version_for_client(
                &server_state.persistence_connection,
                client_mid,
            )
            .await
            {
                Ok(maybe_id) => maybe_id,
                Err(e) => {
                    error!("error fetching last client version for {client_mid}: {e}");
                    None
                }
            }
        },
        |client_token, protocol_version| async move {
            if let Err(e) = event_store::insert_open_event(
                &server_state.persistence_connection,
                &client_token,
                protocol_version,
            )
            .await
            {
                error!(
                    "error inserting open event for {}: {e}",
                    client_token.token.issuance_id()
                );
            };
        },
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
        |client_mid| async move {
            event_store::query_client_keyserved_bp_last_day(
                &server_state.persistence_connection,
                client_mid,
            )
            .await
            .map_err(|e| anyhow::anyhow!(e).context("querying event_store"))
        },
        |client_mid, attempted_bp| async move {
            if let Err(e) = event_store::insert_ratelimit_exceedance(
                &server_state.persistence_connection,
                client_mid,
                attempted_bp,
            )
            .await
            {
                error!(
                    "failed to record ratelimit exceedance of {} for {}: {e}",
                    attempted_bp, client_mid,
                );
            }
        },
        request,
    )
    .await
}

async fn respond_to_monitoring_plane(
    _ks_state: Arc<KeyserverState>,
    _peer: SocketAddr,
    request: Request<Incoming>,
) -> GenericResponse {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => query_server_metrics(),
        _ => response::text(StatusCode::NOT_FOUND, "404 not found"),
    }
}

fn query_server_metrics() -> GenericResponse {
    response::text(StatusCode::OK, get_metrics_output())
}
