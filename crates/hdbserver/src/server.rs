// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs::{self, File};
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Weak};

use anyhow::Context;
use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use certificates::{DatabaseTokenGroup, Issued, Manufacturer};
use hdb::{Database, HazardLookupTable};
use minhttp::error::ErrWrapper;
use minhttp::mpserver::traits::ValidServerSetup;
use minhttp::mpserver::{MultiplaneServer, ServerConfig};
use minhttp::response::{self, ErrResponse, GenericResponse};
use scep_server_helpers::server::ServerState;
use securedna_versioning::version::get_version;
use shared_types::hash::HashSpec;
use shared_types::http::add_cors_headers;
use shared_types::metrics::{get_metrics_output, HdbMetrics};
use shared_types::requests::RequestId;
use shared_types::server_versions::HdbVersion;

use crate::event_store;
use crate::opts::Config;
use crate::state::{BuildTimestamp, HdbServerState};
use crate::validation::NetworkingValidator;

/// SCEP server version
const SERVER_VERSION: u64 = 1;

pub fn server_setup() -> impl ValidServerSetup<Config, HdbServerState> {
    MultiplaneServer::builder()
        .with_reconfigure(reconfigure)
        .with_response(respond)
        .with_response_to_monitoring(respond_to_monitoring_plane)
}

async fn reconfigure(
    server_cfg: ServerConfig<Config>,
    prev_state: Weak<HdbServerState>,
) -> Result<Arc<HdbServerState>, ErrWrapper> {
    let app_cfg = server_cfg.main.custom;
    let prev_state = Weak::upgrade(&prev_state);

    let build_info = get_hdb_build_info(&app_cfg.database);
    match &build_info {
        Ok(build_info) => info!("HDB Build Info: {build_info:?}"),
        Err(err) => warn!("{err:?}"),
    }
    let build_timestamp = build_info.ok().map(|bi| BuildTimestamp(bi.build_timestamp));

    info!("Starting HDB server");
    let database = Database::open(&app_cfg.database).context("failed to open database")?;
    info!("Database is opened!");
    let hlt = HazardLookupTable::read(&app_cfg.database).context("failed to open HLT")?;
    info!("HLT is ready!");

    let manufacturer_roots =
        scep_server_helpers::certs::read_certificates::<Manufacturer>(app_cfg.manufacturer_roots)
            .context("reading manufacturer root certs")?
            .into_iter()
            .map(|c| *c.public_key())
            .collect::<Vec<_>>();

    let token_bundle =
        scep_server_helpers::certs::read_tokenbundle::<DatabaseTokenGroup>(app_cfg.token_file)
            .context("reading database token bundle")?;

    let passphrase = fs::read_to_string(&app_cfg.keypair_passphrase_file)
        .context("reading database keypair passphrase file")?;

    let keypair = scep_server_helpers::certs::read_keypair(app_cfg.keypair_file, passphrase.trim())
        .context("reading database keypair")?;

    let heavy_requests = Arc::new(Semaphore::new(app_cfg.max_heavy_clients));
    let hdb_queries = Arc::new(Semaphore::new(app_cfg.disk_parallelism_per_server));

    // Once metrics are enabled, they can't be disabled.
    // (at least, I don't yet know enough about our metrics code to be sure that's sensible)
    let metrics = if let Some(prev_metrics) = prev_state.as_ref().map(|s| &s.metrics) {
        prev_metrics.clone()
    } else if server_cfg.monitoring.is_some() {
        let m = HdbMetrics::default();
        m.max_clients.set(server_cfg.main.max_connections as i64);
        Some(Arc::new(m))
    } else {
        None
    };

    let hash_spec_json_string = match &app_cfg.hash_spec_path {
        Some(path) => std::fs::read_to_string(path).context("failed to open hash spec file")?,
        None => crate::opts::DEFAULT_HASH_SPEC.to_string(),
    };

    let hash_spec: HashSpec =
        serde_json::from_str(&hash_spec_json_string).context("failed to decode hash spec json")?;
    hash_spec.validate().context("hash spec is invalid")?;

    let validator = NetworkingValidator {
        yubico_api_client_id: app_cfg.yubico_api_client_id,
        yubico_api_secret_key: app_cfg.yubico_api_secret_key,
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

    Ok(Arc::new(HdbServerState {
        build_timestamp,
        database,
        heavy_requests,
        hlt,
        metrics: metrics.clone(),
        hdb_queries,
        parallelism_per_request: app_cfg.disk_parallelism_per_request,
        hash_spec,
        validator,
        scep: ServerState {
            clients: Default::default(),
            json_size_limit: app_cfg.scep_json_size_limit,
            manufacturer_roots,
            token_bundle,
            keypair,
            allow_insecure_cookie: app_cfg.allow_insecure_cookie,
        },
        elt_size_limit: app_cfg.elt_size_limit,
        persistence_path: app_cfg.event_store_path,
        persistence_connection,
    }))
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
    peer: SocketAddr,
    request: Request<Incoming>,
) -> GenericResponse {
    let request_id = RequestId::from(request.headers());
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
                    &request_id,
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
                    &request_id,
                    peer,
                    scep_endpoint_authenticate(&hdbs_state, request),
                ),
            )
            .await
        }
        scep::SCREEN_ENDPOINT | scep::ELT_SCREEN_HASHES_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    peer,
                    crate::screening::scep_endpoint_screen(
                        &request_id,
                        hdbs_state.clone(),
                        request,
                    ),
                ),
            )
            .await
        }
        scep::SCREEN_WITH_EL_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    peer,
                    crate::screening::scep_endpoint_screen_with_el(
                        &request_id,
                        hdbs_state.clone(),
                        request,
                    ),
                ),
            )
            .await
        }
        scep::ELT_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    peer,
                    crate::screening::scep_endpoint_elt(&request_id, hdbs_state.clone(), request),
                ),
            )
            .await
        }
        scep::ELT_SEQ_HASHES_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    peer,
                    crate::screening::scep_endpoint_elt_seq_hashes(
                        &request_id,
                        hdbs_state.clone(),
                        request,
                    ),
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
    let response = HdbVersion {
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
    metrics: &Option<Arc<HdbMetrics>>,
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
    metrics: &Option<Arc<HdbMetrics>>,
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
    _hdbs_state: Arc<HdbServerState>,
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
    server_state: &HdbServerState,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerAuthentication>> {
    scep_server_helpers::server::scep_endpoint_authenticate(
        &server_state.scep,
        SERVER_VERSION,
        |client_mid| async move {
            event_store::query_client_screened_bp_in_last_day(
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

#[cfg(test)]
mod test {
    use super::*;

    use minhttp::mpserver::common::stub_cfg;
    use minhttp::mpserver::{ExternalWorld, PlaneConfig};
    use minhttp::test::FakeNetwork;

    #[tokio::test]
    async fn test_empty_hdb_returns_error() {
        let hdb_dir = tempfile::tempdir().unwrap();
        let network = Arc::new(FakeNetwork::default());

        let app_cfg = Config {
            database: hdb_dir.path().to_owned(),
            max_heavy_clients: Config::default_max_heavy_clients(),
            disk_parallelism_per_server: Config::default_disk_parallelism_per_server(),
            disk_parallelism_per_request: Config::default_disk_parallelism_per_request(),
            hash_spec_path: None,
            yubico_api_client_id: None,
            yubico_api_secret_key: None,
            scep_json_size_limit: Config::default_scep_json_size_limit(),
            elt_size_limit: Config::default_elt_size_limit(),
            manufacturer_roots: "test/certs/manufacturer_roots".into(),
            token_file: "test/certs/database-token.dt".into(),
            keypair_file: "test/certs/database-token.priv".into(),
            keypair_passphrase_file: "test/certs/database-passphrase.txt".into(),
            allow_insecure_cookie: true,
            event_store_path: Config::default_event_store_path(),
        };
        let server_config = ServerConfig {
            main: PlaneConfig {
                address: "192.0.2.2:80".parse().unwrap(),
                max_connections: PlaneConfig::DEFAULT_MAX_CONNECTIONS,
                custom: app_cfg,
            },
            monitoring: None,
            control: None,
        };
        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || server_config.clone()),
        };
        let server = server_setup()
            .to_server_setup()
            .build_with_external_world(external_world);

        // Checking that the HDB/etc is valid happens during a reconfiguration...
        // This should fail because the HDB is empty.
        assert!(server.reload_cfg().await.is_err());
    }
}
