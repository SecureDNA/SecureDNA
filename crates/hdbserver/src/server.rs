// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs::{self, File};
use std::path::Path;
use std::sync::{Arc, Weak};

use anyhow::Context;
use certificates::key_traits::CanLoadSigningKey;
use hdb_api::verification::Verifier;
use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::{Span, error, info, warn};

use certificates::{DatabaseTokenGroup, Exemption, Issued, Manufacturer, VerifierTokenGroup};
use hdb::{Database, HazardLookupTable};
use minhttp::error::ErrWrapper;
use minhttp::mpserver::common::ConnectionTimeouts;
use minhttp::mpserver::traits::ValidServerSetup;
use minhttp::mpserver::{MultiplaneServer, ServerConfig};
use minhttp::peer::Peer;
use minhttp::response::{self, GenericResponse};
use scep_server_helpers::server::ServerState;
use securedna_versioning::version::get_version;
use shared_types::hash::HashSpec;
use shared_types::http::add_cors_headers;
use shared_types::metrics::{HdbMetrics, get_metrics_output};
use shared_types::requests::RequestId;
use shared_types::server_versions::HdbVersion;

use crate::event_store;
use crate::mail::MailService;
use crate::opts::Config;
use crate::state::HdbServerState;
use crate::validation::NetworkingValidator;

/// SCEP server version
const SERVER_VERSION: u64 = 2;

pub fn server_setup() -> impl ValidServerSetup<Config, HdbServerState> {
    MultiplaneServer::builder()
        .with_reconfigure(reconfigure)
        .with_connected(connected)
        .with_response(respond)
        .with_response_to_monitoring(respond_to_monitoring_plane)
}

async fn reconfigure(
    server_cfg: ServerConfig<Config>,
    prev_state: Weak<HdbServerState>,
) -> Result<Arc<HdbServerState>, ErrWrapper> {
    let app_cfg = server_cfg.main.custom;
    let prev_state = Weak::upgrade(&prev_state);

    info!("Attempting load of hdbserver version {}", get_version());

    info!("Starting HDB server");
    // The database-related datastructures (mostly indexes) are rather memory intensive,
    // so we should try to reuse them if the database path hasn't changed. However, we need
    // to be mindful that symlinks could be used to change the database path without
    // changing the config.
    let cfg_database_path = &app_cfg.database;
    let database_path = std::fs::canonicalize(cfg_database_path)
        .with_context(|| format!("Failed to canonicalize database path: {cfg_database_path:?}"))?;
    if cfg_database_path != &database_path {
        info!("Interpreting database path {cfg_database_path:?} as {database_path:?}");
    }
    let version;
    let database;
    let hlt;
    if let Some(previous_state) = prev_state
        .as_ref()
        .filter(|ps| ps.database_path == database_path)
    {
        info!("database path is unchanged from {database_path:?}; reusing existing database");
        version = previous_state.version.clone();
        match &version.hdb_timestamp {
            Some(timestamp) => info!("Existing database was built on {timestamp:?}"),
            None => info!("Existing database has unknown build date."),
        }
        database = previous_state.database.clone();
        hlt = previous_state.hlt.clone();
    } else {
        let build_info = get_hdb_build_info(&app_cfg.database);
        match &build_info {
            Ok(build_info) => info!("HDB Build Info: {build_info:?}"),
            Err(err) => warn!("Couldn't read HDB build info: {err:?}"),
        }
        version = HdbVersion {
            server_version: get_version(),
            hdb_timestamp: build_info.ok().map(|bi| bi.build_timestamp),
        };

        database = Database::open(&database_path)
            .with_context(|| format!("failed to open database: {database_path:?}"))?
            .into();
        info!("Database is opened!");
        hlt = HazardLookupTable::read(&database_path)
            .context("failed to open HLT")?
            .into();
        info!("HLT is ready!");
    }

    let exemptions_roots =
        scep_server_helpers::certs::read_certificates::<Exemption>(app_cfg.exemption_roots)
            .context("reading exemption root certs")?
            .into_iter()
            .map(|c| *c.public_key())
            .collect::<Vec<_>>();

    let manufacturer_roots =
        scep_server_helpers::certs::read_certificates::<Manufacturer>(app_cfg.manufacturer_roots)
            .context("reading manufacturer root certs")?
            .into_iter()
            .map(|c| *c.public_key())
            .collect::<Vec<_>>();

    let revocation_list = if let Some(path) = app_cfg.revocation_list {
        let contents = tokio::fs::read(&path).await;
        (|| -> anyhow::Result<_> {
            let contents = String::from_utf8(contents?)?;
            Ok(toml::from_str(&contents)?)
        })()
        .with_context(|| format!("Unable to read revocation list: {path:?}"))?
    } else {
        Default::default()
    };

    let token_bundle =
        scep_server_helpers::certs::read_tokenbundle::<DatabaseTokenGroup>(app_cfg.token_file)
            .context("reading database token bundle")?;

    let path = &app_cfg.keypair_passphrase_file;
    let passphrase = fs::read_to_string(path)
        .with_context(|| format!("reading database keypair passphrase file: {path:?}"))?;

    let keypair = scep_server_helpers::certs::read_keypair(app_cfg.keypair_file, passphrase.trim())
        .context("reading database keypair")?;

    let heavy_requests = Arc::new(Semaphore::new(app_cfg.max_heavy_clients));
    let hdb_queries = Arc::new(Semaphore::new(app_cfg.disk_parallelism_per_server));

    // Once metrics are enabled, they can't be disabled.
    // (at least, I don't yet know enough about our metrics code to be sure that's sensible)
    let metrics = if let Some(prev_metrics) = prev_state.as_ref().map(|s| &s.metrics) {
        prev_metrics.clone()
    } else if server_cfg.monitoring.is_enabled() {
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

    let token_server_bundle = {
        let path = app_cfg.totp_cert_file;
        let contents = tokio::fs::read_to_string(&path)
            .await
            .context("failed to read TOTP certificate bundle")?;
        certificates::CertificateBundle::<Exemption>::from_file_contents(contents)
            .context("failed to parse TOTP certificate bundle")?
    };

    let totp_access_passphrase = fs::read_to_string(&app_cfg.totp_access_passphrase_file)
        .context("failed to read TOTP access passphrase file")?
        .trim()
        .to_string();

    let validator = NetworkingValidator {
        yubico_api_client_id: app_cfg.yubico_api_client_id,
        yubico_api_secret_key: app_cfg.yubico_api_secret_key,
        token_server_bundle,
        totp_access_passphrase,
    };

    // Validate that the TOTP certificate chains back to exemption roots.
    validator
        .validate_totp_certificate_chain(&exemptions_roots, &revocation_list)
        .context("TOTP certificate chain validation failed")?;

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

    let verifier = match (
        &app_cfg.verifier_token_file,
        &app_cfg.verifier_keypair_passphrase_file,
        &app_cfg.verifier_keypair_file,
        app_cfg.verifier_history_url,
    ) {
        (Some(token_file), Some(passphrase_file), Some(keypair_file), Some(url)) => {
            let token_bundle =
                scep_server_helpers::certs::read_tokenbundle::<VerifierTokenGroup>(token_file)
                    .context("reading database verifier token bundle")?;

            let passphrase = fs::read_to_string(passphrase_file)
                .context("reading database verifier keypair passphrase file")?;

            let keypair = scep_server_helpers::certs::read_keypair(keypair_file, passphrase.trim())
                .context("reading database verifier keypair")?;

            let token = token_bundle
                .token
                .load_key(keypair)
                .context("loading verifier key")?;

            Some(Verifier::new(token, url))
        }
        (None, None, None, None) => None,
        _ => {
            return Err(anyhow::anyhow!(
                "If any of --verifier-token-file, --verifier-keypair-passphrase-file, \
                --verifier-keypair-file, or --verifier-history-url is specified, \
                all of them must be specified."
            )
            .into());
        }
    };

    let mail_service = match (
        &app_cfg.audit_smtp2go_api_key_file,
        &app_cfg.audit_template_file,
    ) {
        (Some(api_key_path), Some(template_path)) => {
            let api_key = tokio::fs::read_to_string(api_key_path)
                .await
                .context("failed to open smtp2go API key file")?
                .trim()
                .to_string();
            let audit_template_toml = tokio::fs::read_to_string(template_path)
                .await
                .context("failed to open audit template file")?;
            let audit_template = toml::from_str(&audit_template_toml)
                .context("failed to read audit template TOML file")?;

            Some(MailService {
                smtp2go_api_key: api_key,
                audit_template,
            })
        }
        (None, None) => {
            warn!(
                "Starting without audit email configuration because --audit-smtp2go-api-key-file \
                (or SECUREDNA_HDBSERVER_AUDIT_SMTP2GO_API_KEY_FILE) is not set. \
                Any requests that would necessitate sending audit email will be denied!"
            );
            None
        }
        _ => {
            return Err(anyhow::anyhow!(
                "If either of --audit-smtp2go-api-key-file or --audit-template-file is specified, \
                both of them must be specified."
            )
            .into());
        }
    };

    let connection_timeouts = ConnectionTimeouts {
        soft: app_cfg.soft_timeout.map(|d| d.0),
        hard: app_cfg.hard_timeout.map(|d| d.0),
        hashes_per_sec: app_cfg.hashes_per_sec_timeout,
    };

    Ok(Arc::new(HdbServerState {
        version,
        database_path,
        database,
        hlt,
        heavy_requests,
        metrics: metrics.clone(),
        hdb_queries,
        parallelism_per_request: app_cfg.disk_parallelism_per_request,
        hash_spec,
        validator,
        scep: ServerState {
            clients: Default::default(),
            json_size_limit: app_cfg.scep_json_size_limit,
            request_hash_limit: app_cfg.scep_hash_limit,
            manufacturer_roots,
            revocation_list,
            token_bundle,
            keypair,
            allow_insecure_cookie: app_cfg.allow_insecure_cookie,
        },
        et_size_limit: app_cfg.et_size_limit,
        exemptions_roots,
        persistence_path: app_cfg.event_store_path,
        persistence_connection,
        verifier,
        mail_service,
        connection_timeouts,
    }))
}

#[allow(dead_code)]
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

fn connected(app_state: Arc<HdbServerState>, peer: Peer) {
    peer.set_timeouts(app_state.connection_timeouts.for_new_connection());
}

#[tracing::instrument(skip_all, fields(request_id))]
async fn respond(
    hdbs_state: Arc<HdbServerState>,
    peer: Peer,
    request: Request<Incoming>,
) -> GenericResponse {
    let request_id = RequestId::from(request.headers());
    Span::current().record("request_id", &request_id.0);
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
        "/robots.txt" => handle_get(&method, robots_txt()).await,
        scep::OPEN_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    &peer,
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
                    &peer,
                    scep_endpoint_authenticate(&hdbs_state, request),
                ),
            )
            .await
        }
        scep::SCREEN_ENDPOINT | scep::EXEMPTION_SCREEN_HASHES_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    &peer,
                    crate::screening::scep_endpoint_screen(
                        &peer,
                        &request_id,
                        hdbs_state.clone(),
                        request,
                    ),
                ),
            )
            .await
        }
        scep::SCREEN_WITH_EXEMPTION_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    &peer,
                    crate::screening::scep_endpoint_screen_with_exemption(
                        &request_id,
                        hdbs_state.clone(),
                        request,
                    ),
                ),
            )
            .await
        }
        scep::EXEMPTION_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    &peer,
                    crate::screening::scep_endpoint_exemption(
                        &request_id,
                        hdbs_state.clone(),
                        request,
                    ),
                ),
            )
            .await
        }
        scep::EXEMPTION_SEQ_HASHES_ENDPOINT => {
            handle_post(
                &method,
                handle_scep_err(
                    &hdbs_state.metrics,
                    &request_id,
                    &peer,
                    crate::screening::scep_endpoint_exemption_seq_hashes(
                        &peer,
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
    let response = hdbs_state.version.clone();
    // this serialization can't fail
    let json = serde_json::to_string(&response).unwrap();
    response::json(StatusCode::OK, json)
}

async fn robots_txt() -> GenericResponse {
    response::text(StatusCode::OK, "User-agent: *\nDisallow: /\n")
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
    future: impl Future<Output = Result<GenericResponse, GenericResponse>>,
) -> GenericResponse {
    let result_response = future.await;
    match (result_response, &metrics) {
        (Err(r), Some(metrics)) => {
            metrics.bad_requests.inc();
            r
        }
        (Ok(r) | Err(r), _) => r,
    }
}

async fn handle_scep_err<F, E>(
    metrics: &Option<Arc<HdbMetrics>>,
    request_id: &RequestId,
    peer: &Peer,
    future: F,
) -> GenericResponse
where
    F: Future<Output = Result<GenericResponse, scep::error::ScepError<E>>>,
    E: std::error::Error + 'static,
{
    let result_response = future.await;
    match result_response {
        Ok(r) => r,
        Err(e) => {
            peer.graceful_shutdown();
            let r = scep_server_helpers::log_and_convert_scep_error_to_response(
                &e,
                request_id,
                peer.addr(),
            );
            if let Some(metrics) = metrics {
                metrics.bad_requests.inc();
            }
            r
        }
    }
}

async fn respond_to_monitoring_plane(
    _hdbs_state: Arc<HdbServerState>,
    _peer: Peer,
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
        |synth_token| {
            let not_benchtop = synth_token.serial_number().trim().is_empty();
            let client_mid = *synth_token.issuance_id();
            async move {
                // Allow version skew in centralized provider setups, which might share tokens
                // across several containers, but don't allow rollbacks in individual benchtops,
                // which must use individualized tokens.
                if not_benchtop {
                    return None;
                }

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
                    "failed to record ratelimit exceedance of {attempted_bp} for {client_mid}: {e}",
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

    use minhttp::mpserver::common::{read_no_disk, stub_cfg};
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
            scep_hash_limit: Config::default_scep_hash_limit(),
            et_size_limit: Config::default_et_size_limit(),
            exemption_roots: "test/certs/exemption-roots".into(),
            manufacturer_roots: "test/certs/manufacturer-roots".into(),
            revocation_list: None,
            token_file: "test/certs/database-token.dt".into(),
            keypair_file: "test/certs/database-token.priv".into(),
            keypair_passphrase_file: "test/certs/database-token.passphrase".into(),
            allow_insecure_cookie: true,
            event_store_path: Config::default_event_store_path(),
            audit_smtp2go_api_key_file: None,
            audit_template_file: None,
            verifier_token_file: Some("test/certs/verifier-token.vt".into()),
            verifier_keypair_file: Some("test/certs/verifier-token.priv".into()),
            verifier_keypair_passphrase_file: Some("test/certs/verifier-token.passphrase".into()),
            // We don't talk to the TOTP server, so we can use any dummy cert here,
            // as long as it chains back to the exemption roots.
            totp_cert_file: "test/certs/exemption-leaf.cert".into(),
            totp_access_passphrase_file: "test/certs/totp-access.passphrase".into(),
            verifier_history_url: Some("https://example.com".into()),
            soft_timeout: None,
            hard_timeout: None,
            hashes_per_sec_timeout: None,
        };
        let server_config = ServerConfig {
            main: PlaneConfig {
                address: Some("192.0.2.2:80".parse().unwrap()),
                tls_config: None,
                max_connections: PlaneConfig::DEFAULT_MAX_CONNECTIONS,
                custom: app_cfg,
            },
            monitoring: PlaneConfig::default(),
            control: PlaneConfig::default(),
        };
        let external_world = ExternalWorld {
            listen: network.listen_fn(),
            load_cfg: stub_cfg(move || server_config.clone()),
            read_file: read_no_disk,
        };
        let server = server_setup()
            .to_server_setup()
            .build_with_external_world(external_world);

        // Checking that the HDB/etc is valid happens during a reconfiguration...
        // This should fail because the HDB is empty.
        assert!(server.reload_cfg().await.is_err());
    }
}
