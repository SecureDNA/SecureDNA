// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs::{self, File};
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use futures::FutureExt;
use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, info_span, warn, Instrument};

use certificates::{DatabaseTokenGroup, Issued, Manufacturer, SynthesizerTokenGroup, TokenBundle};
use hdb::{self, Database, HazardLookupTable};
use minhttp::response::{self, ErrResponse, GenericResponse};
use minhttp::signal::{fast_shutdown_requested, graceful_shutdown_requested};
use minhttp::Server;
use scep_server_helpers::server::ServerState;
use securedna_versioning::version::get_version;
use shared_types::hash::HashSpec;
use shared_types::http::add_cors_headers;
use shared_types::metrics::{get_metrics_output, HDBMetrics};
use shared_types::requests::RequestId;
use shared_types::server_versions::HDBVersion;

use crate::event_store;
use crate::opts::Opts;
use crate::state::{BuildTimestamp, HdbServerState};
use crate::validation::NetworkingValidator;

/// SCEP server version
const SERVER_VERSION: u64 = 1;

pub async fn run(opts: Opts, post_setup_hook: impl Future<Output = ()>) -> anyhow::Result<()> {
    let build_info = get_hdb_build_info(&opts.database);
    match &build_info {
        Ok(build_info) => info!("HDB Build Info: {build_info:?}"),
        Err(err) => warn!("{err:?}"),
    }
    let build_timestamp = build_info.ok().map(|bi| BuildTimestamp(bi.build_timestamp));

    info!("Starting HDB server");
    let database = Database::open(&opts.database).expect("failed to open database");
    info!("Database is opened!");
    let hlt = HazardLookupTable::read(&opts.database).expect("failed to open HLT");
    info!("HLT is ready!");

    let manufacturer_roots =
        scep_server_helpers::certs::read_certificates::<Manufacturer>(opts.manufacturer_roots)
            .context("reading manufacturer root certs")?
            .into_iter()
            .map(|c| *c.public_key())
            .collect::<Vec<_>>();

    let token_bundle =
        scep_server_helpers::certs::read_tokenbundle::<DatabaseTokenGroup>(opts.token_file)
            .context("reading database token bundle")?;

    let passphrase = fs::read_to_string(&opts.keypair_passphrase_file)
        .context("reading database keypair passphrase file")?;

    let keypair = scep_server_helpers::certs::read_keypair(opts.keypair_file, passphrase.trim())
        .context("reading database keypair")?;

    let heavy_requests = Arc::new(Semaphore::new(opts.max_heavy_clients));
    let hdb_queries = Arc::new(Semaphore::new(opts.disk_parallelism_per_server));

    let metrics = opts.monitoring_plane_port.map(|_| {
        let m = HDBMetrics::default();
        m.max_clients.set(opts.max_clients as i64);
        Arc::new(m)
    });

    let hash_spec_json_string = match &opts.hash_spec_path {
        Some(path) => std::fs::read_to_string(path).expect("failed to open hash spec file"),
        None => crate::opts::DEFAULT_HASH_SPEC.to_string(),
    };

    let hash_spec: HashSpec =
        serde_json::from_str(&hash_spec_json_string).expect("failed to decode hash spec json");
    hash_spec.validate().expect("hash spec is invalid");

    let validator = NetworkingValidator {
        yubico_api_client_id: opts.yubico_api_client_id,
        yubico_api_secret_key: opts.yubico_api_secret_key,
    };

    let persistence_connection = crate::event_store::open_db(opts.persistence_path)
        .await
        .context("opening event_store db")?;

    let hdbs_state = Arc::new(HdbServerState {
        build_timestamp,
        database,
        heavy_requests,
        hlt,
        metrics: metrics.clone(),
        hdb_queries,
        parallelism_per_request: opts.disk_parallelism_per_request,
        hash_spec,
        validator,
        scep: ServerState {
            clients: Default::default(),
            json_size_limit: 100_000,
            manufacturer_roots,
            token_bundle,
            keypair,
            allow_insecure_cookie: opts.allow_insecure_cookie,
        },
        persistence_connection,
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

    let run = server
        .with_callbacks()
        .respond(move |request, peer| {
            let hdbs_state = hdbs_state.clone();
            let request_id = RequestId::from(request.headers());
            async move { respond(hdbs_state.clone(), &request_id, request, peer).await }
        })
        .connected(|_| metrics.as_ref().map(|m| m.connected_clients()))
        .failed(move |_| {
            // Apparently hdbservers don't track bad requests?
            // if let Some(m) = metrics2 {
            //     m.bad_requests.inc();
            // }
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

#[derive(Debug, Deserialize)]
pub struct BuildInfo {
    pub build_timestamp: String,
    pub pipeline_git_sha: String,
    pub pipeline_git_timestamp: String,
    pub hdb_git_sha: String,
}

fn get_hdb_build_info(database: &Path) -> anyhow::Result<BuildInfo> {
    let f = File::open(database.join("BUILD_INFO.json"))
        .context("Could not find BUILD_INFO.json file")?;
    serde_json::from_reader(f).context("Could not parse BUILD_INFO.json file.")
}

async fn respond(
    hdbs_state: Arc<HdbServerState>,
    request_id: &RequestId,
    request: Request<Incoming>,
    peer: SocketAddr,
) -> GenericResponse {
    let method = request.method().clone();
    let headers = request.headers().clone();
    let mut response = match request.uri().path() {
        "/qualification" => {
            handle_post(
                &method,
                handle_err(
                    &hdbs_state.metrics,
                    crate::qualification::qualification(&hdbs_state, request),
                ),
            )
            .await
        }
        "/version" => handle_get(&method, version(&hdbs_state)).await,
        scep::OPEN_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    request_id,
                    peer,
                    scep_endpoint_open(&hdbs_state, request),
                ),
            )
            .await
        }
        scep::AUTHENTICATE_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    request_id,
                    peer,
                    scep_endpoint_authenticate(&hdbs_state, request),
                ),
            )
            .await
        }
        scep::SCREEN_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    request_id,
                    peer,
                    crate::screening::scep_endpoint_screen(request_id, hdbs_state.clone(), request),
                ),
            )
            .await
        }
        _ => response::not_found(),
    };
    add_cors_headers(&headers, response.headers_mut());
    response
}

async fn version(hdbs_state: &HdbServerState) -> GenericResponse {
    let server_version = get_version();
    let hdb_timestamp = hdbs_state.build_timestamp.clone().map(|t| t.0);
    let response = HDBVersion {
        server_version,
        hdb_timestamp,
    };
    // this serialization can't fail
    let json = serde_json::to_string(&response).unwrap();
    response::json(StatusCode::OK, json)
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
    metrics: &Option<Arc<HDBMetrics>>,
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
    metrics: &Option<Arc<HDBMetrics>>,
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

async fn scep_endpoint_open(
    server_state: &HdbServerState,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerPrevalidation>> {
    scep_server_helpers::server::scep_endpoint_open(
        &server_state.scep,
        SERVER_VERSION,
        &server_state.hash_spec,
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
        |client_mid, protocol_version| async move {
            if let Err(e) = event_store::insert_open_event(
                &server_state.persistence_connection,
                client_mid,
                protocol_version,
            )
            .await
            {
                error!("error inserting open event for {client_mid}: {e}");
            };
        },
        request,
    )
    .await
}

async fn scep_endpoint_authenticate(
    server_state: &HdbServerState,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerAuthentication>> {
    scep_server_helpers::server::scep_endpoint_authenticate(
        &server_state.scep,
        SERVER_VERSION,
        |client_mid| async move {
            event_store::query_client_screened_bp_last_day(
                &server_state.persistence_connection,
                client_mid,
            )
            .await
            .map_err(|e| anyhow::anyhow!(e).context("querying event_store"))
        },
        |client_tokenbundle: TokenBundle<SynthesizerTokenGroup>, attempted_bp| async move {
            if let Err(e) = event_store::insert_ratelimit_exceedance(
                &server_state.persistence_connection,
                &client_tokenbundle,
                attempted_bp,
            )
            .await
            {
                error!(
                    "failed to record ratelimit exceedance of {} for {}: {e}",
                    attempted_bp,
                    client_tokenbundle.token.issuance_id()
                );
            }
        },
        request,
    )
    .await
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::Parser;

    #[tokio::test]
    #[should_panic]
    async fn test_empty_hdb_returns_error() {
        // since the panic happens inside the `run` fn, can't inspect the returned error. Consider
        // removing the panic in `run`.
        let hdb_dir = tempfile::tempdir().unwrap();
        let opts = crate::opts::Opts::parse_from(vec![
            "hdbserver".to_string(),
            "--manufacturer-roots".to_string(),
            "test/certs/manufacturer_roots".to_string(),
            "--token-file".to_string(),
            "test/certs/database-token.dt".to_string(),
            "--keypair-file".to_string(),
            "test/certs/database-token.priv".to_string(),
            "--keypair-passphrase-file".to_string(),
            "test/certs/database-passphrase.txt".to_string(),
            hdb_dir.path().display().to_string(),
        ]);
        run(opts, async {}).await.unwrap();
    }
}
