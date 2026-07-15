// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};

use anyhow::Context;
use bytes::Bytes;
use certificates::{ChainTraversal, ExemptionTokenGroup, HierarchyKind, SystemClock, TokenBundle};
use doprf_client::ScreeningParams;
use futures::FutureExt;
use futures::future::join_all;
use http_body_util::BodyExt;
use http_client::BaseApiClient;
use hyper::body::{Body, Incoming};
use hyper::{Method, Request, StatusCode, Uri};
use serde::de::DeserializeOwned;
use sha3::{Digest, Sha3_256};
use shared_types::error::InvalidClientTokenBundle;
use shared_types::et::WithOtps;
use tokio::sync::{Mutex, Semaphore};
use tracing::{error, info};

use doprf::party::KeyserverId;
use doprf_client::RequestStreaming;
use doprf_client::server_selection::ServerSelector;
use doprf_client::server_version_handler::LastServerVersionHandler;
use http_client::service::util::force_http_if;
use minhttp::error::ErrWrapper;
use minhttp::mpserver::traits::ValidServerSetup;
use minhttp::mpserver::{MultiplaneServer, ServerConfig};
use minhttp::peer::Peer;
use minhttp::response::{self, GenericResponse};
use quickdna::NucleotideAmbiguous;
use securedna_versioning::version::get_version;
use shared_types::http::add_cors_headers;
use shared_types::metrics::{SynthClientMetrics, get_metrics_output};
use shared_types::requests::RequestId;
use shared_types::server_versions::{HdbVersion, KeyserverVersion};

use crate::api::{
    ApiError, ApiResponse, CheckFastaRequest, CheckNcbiRequest, RequestCommon, SynthesisPermission,
    VersionInfo,
};
use crate::api_version;
use crate::ncbi::download_fasta_by_acc_number;
use crate::parsefasta::{CheckerConfiguration, CurrentSystemLoadTracker, check_fasta};
use crate::rate_limiter::{RateLimiter, SystemTimeHourProvider};
use crate::recaptcha::validate_recaptcha;
use crate::server_selection::initialize_server_selector;
use crate::web_cache::WebCache;

use crate::shims::types::{Config, SynthClientState};

use super::types::ScreeningType;

pub fn server_setup() -> impl ValidServerSetup<Config, SynthClientState> {
    MultiplaneServer::builder()
        .with_reconfigure(reconfigure)
        .with_response(respond)
        .with_response_to_monitoring(respond_to_monitoring_plane)
}

async fn reconfigure(
    server_cfg: ServerConfig<Config>,
    prev_state: Weak<SynthClientState>,
) -> Result<Arc<SynthClientState>, ErrWrapper> {
    let app_cfg = server_cfg.main.custom;
    let prev_state = Weak::upgrade(&prev_state);

    info!("Attempting load of synthclient version {}", get_version());

    if let Some(limit) = app_cfg.memorylimit {
        info!("Running with memory limit: {limit}B");
    }

    let certs = Arc::new(app_cfg.certs.validate_and_build()?);

    info!("Initializing server selector...");
    let request_id = RequestId::new_unique_with_prefix("server-selection");
    let (service, worker) = http_client::securedna_service_and_worker(request_id)
        .context("Couldn't generate valid request ID for server selection")?;
    // Not a fan of tasks outliving parents, but this requires the least architectural change.
    // On the bright side, `worker` will automatically terminate when `service` is dropped,
    // such as when there's a config reload and all old requests finish.
    // Also, assuming this code is only ever run outside of WASM, `service` won't actually
    // outsource its requests to `worker`, so `worker` will be a no-op.
    tokio::spawn(worker);
    let service = force_http_if(service, app_cfg.use_http);
    let server_selector = initialize_server_selector(service.into(), &app_cfg)
        .await
        .context("Unable to initialize server selector")?;
    info!("Finished initializing server selector");

    // Once metrics are enabled, they can't be disabled.
    // (at least, I don't yet know enough about our metrics code to be sure that's sensible)
    let metrics = if let Some(prev_metrics) = prev_state.as_ref().map(|s| &s.metrics) {
        prev_metrics.clone()
    } else if server_cfg.monitoring.is_enabled() {
        let m = SynthClientMetrics::default();
        let max_clients: i64 = server_cfg.main.max_connections.into();
        m.max_clients.set(max_clients);
        Some(Arc::new(m))
    } else {
        None
    };

    let limits = CurrentSystemLoadTracker {
        current_base_pair_counter: AtomicUsize::new(0),
    };

    let rate_limiter = Mutex::new(RateLimiter::<IpAddr, _>::new(
        app_cfg.recaptcha_requests_per_hour,
        SystemTimeHourProvider,
    ));

    let synthclient_version = securedna_versioning::version::get_version();

    let persistence_connection = if let Some(prev_state) = prev_state {
        if app_cfg.event_store_path != prev_state.app_cfg.event_store_path {
            return Err(anyhow::anyhow!(
                "Changes to event_store_path not supported: expected {:?}, but found {:?}",
                prev_state.app_cfg.event_store_path,
                app_cfg.event_store_path,
            )
            .into());
        }
        prev_state.persistence_connection.clone()
    } else {
        let connection = crate::shims::event_store::open_db(&app_cfg.event_store_path)
            .await
            .context("opening event store db")?;
        Arc::new(connection)
    };

    let web_cache = Arc::new(WebCache::new(
        BaseApiClient::new_external(),
        app_cfg.frontend_url.clone(),
    ));

    if let Some(path) = &app_cfg.store_verifiable_results {
        // Actually try writing to it:
        let test_dir = path.join("test");
        if let Err(e) = tokio::fs::create_dir_all(&test_dir).await {
            return Err(anyhow::anyhow!(
                "Couldn't create a test directory to {}: {e}. Try adjusting store_verifiable_results to a writable directory (currently {})", test_dir.to_string_lossy(), path.to_string_lossy()
            ).into());
        }
        let test_path = test_dir.join("example.json");
        if let Err(e) = tokio::fs::write(&test_path, "{}").await {
            return Err(anyhow::anyhow!(
                "Couldn't write a test file to {}: {e}. Try adjusting store_verifiable_results to a writable directory (currently {})", test_path.to_string_lossy(), path.to_string_lossy()
            ).into());
        }

        // Try cleaning up our test file, but don't care too much if this fails. The important part is that we can write files.
        let _ = tokio::fs::remove_file(&test_path).await;
        let _ = tokio::fs::remove_dir(&test_dir).await;
    }

    let available_parallelism = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    info!("Available parallelism: {available_parallelism}");
    let default_parallelism = available_parallelism.saturating_add(available_parallelism.get());
    let parallelism_per_request = app_cfg
        .crypto_parallelism_per_request
        .unwrap_or(default_parallelism);
    info!("Per-request parallelism: {parallelism_per_request}");
    let server_parallelism = app_cfg
        .crypto_parallelism_per_server
        .unwrap_or(default_parallelism);
    info!("Server-wide parallelism: {server_parallelism}");
    let server_parallelism_limit = Arc::new(Semaphore::new(server_parallelism.get()));

    Ok(Arc::new(SynthClientState {
        app_cfg,
        is_serving_https: server_cfg.main.tls_config.is_some(),
        server_selector: Arc::new(server_selector),
        metrics: metrics.clone(),
        limits,
        demo_rate_limiter: rate_limiter,
        certs,
        synthclient_version,
        persistence_connection,
        web_cache,
        parallelism_per_request,
        server_parallelism_limit,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScreenSource {
    Fasta,
    FastaDemo,
    Ncbi,
}

impl ScreenSource {
    fn screening_type(&self) -> ScreeningType {
        match self {
            Self::Fasta => ScreeningType::Normal,
            Self::FastaDemo => ScreeningType::Demo,
            Self::Ncbi => ScreeningType::Normal,
        }
    }

    fn new(path: &str, require_captcha: bool) -> Option<Self> {
        match (path, require_captcha) {
            (concat!("/v", api_version!(), "/screen"), false) => Some(Self::Fasta),
            (concat!("/v", api_version!(), "/screen"), true) => Some(Self::FastaDemo),
            (concat!("/v", api_version!(), "/ncbi"), _) => Some(Self::Ncbi),
            _ => None,
        }
    }
}

async fn respond(
    sc_state: Arc<SynthClientState>,
    peer: Peer,
    request: Request<Incoming>,
) -> GenericResponse {
    let peer = peer.addr();
    let method = request.method().clone();
    let headers = request.headers().clone();
    let path = request.uri().path();
    let screen_source = ScreenSource::new(path, sc_state.app_cfg.require_captcha);

    let mut response = match (method, screen_source, path) {
        (Method::OPTIONS, _, _) => response::empty(),
        (Method::GET, _, "/version") => query_server_version(&sc_state).await,
        (Method::GET, _, _path) => proxy_web_interface(&sc_state, request).await,
        (Method::POST, Some(source), _) => {
            let mut provider_reference: Option<String> = None;
            match screen(source, &sc_state, peer, request, &mut provider_reference).await {
                Ok(api_response) => json_api_response(StatusCode::OK, api_response),
                Err(api_error) => json_api_error(api_error, provider_reference),
            }
        }
        (_, _, path) => json_api_error(ApiError::not_found(path.to_owned()), None),
    };

    add_cors_headers(&headers, response.headers_mut());
    response
}

async fn respond_to_monitoring_plane(
    _sc_state: Arc<SynthClientState>,
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

/// Uses the common request fields to validate the API key, generate a RequestId, and
/// log the request_id / provider_reference so they can be correlated.
async fn init_request(common: &RequestCommon) -> RequestId {
    let request_id = RequestId::new_unique();

    // TODO: this should be associated with the request tracing span eventually,
    //       but we haven't gotten tracing working yet
    info!(
        "{}: validated request with provider_reference={:?} and region={:?}",
        request_id, common.provider_reference, common.region
    );

    request_id
}

fn str_param(uri: &Uri, name: &str) -> Option<String> {
    if let Some(query) = uri.query() {
        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            if k == name {
                return Some(v.into_owned());
            }
        }
    }
    None
}

fn bool_param(uri: &Uri, name: &str) -> bool {
    matches!(
        str_param(uri, name).as_deref(),
        Some("true") | Some("TRUE") | Some("1") | Some("")
    )
}

async fn check_and_extract_json_body(body: Incoming, size_limit: u64) -> Result<Bytes, ApiError> {
    match body.size_hint().exact() {
        Some(n) => {
            if n > size_limit {
                return Err(ApiError::request_body_too_big(size_limit));
            }
        }
        None => return Err(ApiError::request_lacks_content_length()),
    }
    let bytes = body
        .collect()
        .await
        .map_err(|e| {
            error!("failed to collect body: {e}");
            ApiError::generic_internal_server_error()
        })?
        .to_bytes();
    Ok(bytes)
}

async fn proxy_web_interface(
    state: &SynthClientState,
    request: Request<Incoming>,
) -> GenericResponse {
    state
        .web_cache
        .get(request.uri().path())
        .await
        .unwrap_or_else(|_| {
            json_api_error(
                match request.uri().path() {
                    "" | "/" | "/index.html" => {
                        ApiError::root_not_found(&state.app_cfg.frontend_url)
                    }
                    _ => ApiError::not_found(request.uri()),
                },
                None,
            )
        })
}

async fn screen(
    source: ScreenSource,
    state: &SynthClientState,
    peer: SocketAddr,
    request: Request<Incoming>,
    out_provider_reference: &mut Option<String>,
) -> Result<ApiResponse, ApiError> {
    let (parts, body) = request.into_parts();
    let body = check_and_extract_json_body(body, state.app_cfg.json_size_limit).await?;

    let _gauge = state.metrics.as_ref().map(|m| m.connected_clients());
    if let Some(m) = state.metrics.as_ref() {
        m.requests.inc();
    }

    let (fasta, common, request_id) = match source {
        ScreenSource::Ncbi => {
            let CheckNcbiRequest { id, common } = serde_json::from_slice(&body)?;
            out_provider_reference.clone_from(&common.provider_reference);
            let request_id = init_request(&common).await;

            info!("{request_id}: begin fetching {id} from NCBI");
            let fasta = download_fasta_by_acc_number(&request_id, id).await?;
            info!(
                "{}: begin checking NCBI FASTA (length {})",
                request_id,
                fasta.len()
            );
            (fasta, common, request_id)
        }
        ScreenSource::Fasta | ScreenSource::FastaDemo => {
            let CheckFastaRequest { fasta, common } = serde_json::from_slice(&body)?;
            out_provider_reference.clone_from(&common.provider_reference);
            let request_id = init_request(&common).await;

            if source == ScreenSource::FastaDemo {
                let client_ip = peer.ip();
                let recaptcha_token = str_param(&parts.uri, "recaptcha_token").unwrap_or_default();

                info!(
                    "{request_id}: screen ({source:?}) client_ip={client_ip}, recaptcha_token={recaptcha_token}",
                );

                let secret = state.app_cfg.recaptcha_secret_key.as_deref();
                validate_recaptcha(&recaptcha_token, secret, client_ip).await?;
                state.demo_rate_limiter.lock().await.request(client_ip)?;
            }

            (fasta, common, request_id)
        }
    };

    let (service, worker) = http_client::securedna_service_and_worker(request_id.clone())?;
    let service = force_http_if(service, state.app_cfg.use_http);
    let api_client = service.into();

    let debug_info = bool_param(&parts.uri, "debug_info");

    let server_version_handler = LastServerVersionHandler::new(
        {
            let connection = state.persistence_connection.clone();
            Box::new(move |domain| {
                let connection = connection.clone();
                Box::pin(async move {
                    Ok(super::event_store::query_last_server_version(&connection, domain).await?)
                })
            })
        },
        {
            let connection = state.persistence_connection.clone();
            Box::new(move |domain, server_version| {
                let connection = connection.clone();
                Box::pin(async move {
                    Ok(super::event_store::upsert_server_version(
                        &connection,
                        domain,
                        server_version,
                    )
                    .await?)
                })
            })
        },
    );

    type Et = WithOtps<TokenBundle<ExemptionTokenGroup>>;
    let ets: Vec<Et> = common
        .ets
        .into_iter()
        .map(|et| et.try_map(TokenBundle::<ExemptionTokenGroup>::from_file_contents))
        .collect::<Result<Vec<_>, _>>()?;

    for WithOtps { et, .. } in &ets {
        et.path_to_cert_with_hierarchy_level(&HierarchyKind::Intermediate, &SystemClock)
            .map_err(|err| InvalidClientTokenBundle {
                error: err,
                token_kind: certificates::TokenKind::Exemption,
            })?;
    }

    let fasta_sha3_256_hex = hex::encode(Sha3_256::new().chain_update(&body).finalize());

    let config = CheckerConfiguration {
        api_client,
        request_streaming: RequestStreaming::Bidirectional,
        server_selector: Arc::clone(&state.server_selector),
        metrics: state.metrics.as_ref().map(Arc::clone),
        limit_config: state.limit_config(source.screening_type()),
        synthclient_version_hint: &state.synthclient_version,
        server_version_handler,
        params: ScreeningParams {
            certs: Arc::clone(&state.certs),
            include_debug_info: debug_info,
            region: common.region.into(),
            verifiable_screening: common.verifiable_screening,
            ets,
            fasta_sha3_256_hex,
            synthclient_version: state.synthclient_version.clone(),
        },
        provider_reference: common.provider_reference,
        parallelism_per_request: state.parallelism_per_request,
        server_parallelism_limit: state.server_parallelism_limit.clone(),
    };

    let check_fasta = check_fasta::<NucleotideAmbiguous>(&request_id, fasta, &config);
    let api_response = tokio::join!(check_fasta, worker).0?;

    info!(
        "{}: finished, status = {:?}",
        request_id, api_response.synthesis_permission
    );

    if let Some(path) = &state.app_cfg.store_verifiable_results {
        let time = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| {
                info!("{request_id}: can't format timestamp: {e}");
                ApiError::generic_internal_server_error()
            })?
            .replace(':', "_");
        let subpath = path.join(time);
        let _ = tokio::fs::create_dir_all(&subpath).await;
        tokio::fs::write(subpath.join("request.json"), body)
            .await
            .map_err(|e| {
                info!("{request_id}: can't write request to disk: {e}");
                ApiError::generic_internal_server_error()
            })?;
        let response = serde_json::to_string(&api_response).map_err(|e| {
            info!("{request_id}: can't convert response to JSON: {e}");
            ApiError::generic_internal_server_error()
        })?;
        tokio::fs::write(subpath.join("response.json"), response)
            .await
            .map_err(|e| {
                info!("{request_id}: can't write response to disk: {e}");
                ApiError::generic_internal_server_error()
            })?;
    }

    Ok(api_response)
}

async fn query_server_version(state: &SynthClientState) -> GenericResponse {
    let synthclient_version = get_version();
    let hdb_version = get_hdb_version(state.server_selector.clone(), state.app_cfg.use_http).await;
    let (hdbserver_version, hdb_timestamp) = match hdb_version {
        Some(v) => (Some(v.server_version), v.hdb_timestamp),
        None => (None, None),
    };
    let keyserver_versions =
        get_keyserver_versions(state.server_selector.clone(), state.app_cfg.use_http).await;

    // this serialization can't fail
    let json = serde_json::to_string(&VersionInfo {
        synthclient_version,
        hdbserver_version,
        hdb_timestamp,
        keyserver_versions,
    })
    .unwrap();
    response::json(StatusCode::OK, json)
}

async fn get_json_version<T: DeserializeOwned>(url: impl AsRef<str>) -> Option<T> {
    let url = url.as_ref();
    let response = reqwest::get(url)
        .await
        .inspect_err(|err| info!("error when getting {url}: {err}"))
        .ok()?;
    let status = response.status();
    let text = response
        .text()
        .await
        .inspect_err(|err| info!("error when getting text from {url}: {err}"))
        .ok()?;

    if status != reqwest::StatusCode::OK {
        info!("{url} returned non-200 response: {text}");
        return None;
    }
    match serde_json::from_str(&text) {
        Ok(hdb_version) => Some(hdb_version),
        Err(err) => {
            info!("{url} returned unparsesable response: {err} (from {text:?})",);
            None
        }
    }
}

async fn get_hdb_version(
    server_selector: Arc<ServerSelector>,
    use_http: bool,
) -> Option<HdbVersion> {
    let current_hdb = server_selector.choose().await.ok()?.hdb;
    let scheme = if use_http { "http" } else { "https" };
    let url = format!("{scheme}://{}/version", current_hdb.domain);
    get_json_version(url).await
}

async fn get_keyserver_versions(
    server_selector: Arc<ServerSelector>,
    use_http: bool,
) -> Option<Vec<(KeyserverId, Option<String>)>> {
    let current_keyservers = server_selector.choose().await.ok()?.keyservers;
    let scheme = if use_http { "http" } else { "https" };
    let futures = current_keyservers.iter().map(|ks| {
        let url = format!("{scheme}://{}/version", ks.domain);
        get_json_version::<KeyserverVersion>(url)
            .map(move |response| (ks.id, response.map(|v| v.server_version)))
    });
    let mut versions = join_all(futures).await;
    versions.sort();
    Some(versions)
}

fn json_api_response(status_code: StatusCode, api_response: ApiResponse) -> GenericResponse {
    // This serialization can't fail.
    let body = serde_json::to_string(&api_response).unwrap();
    response::json(status_code, body)
}

fn json_api_error(api_error: ApiError, provider_reference: Option<String>) -> GenericResponse {
    let status_code = api_error
        .status_code()
        .try_into()
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let api_response = ApiResponse {
        synthesis_permission: SynthesisPermission::Denied,
        provider_reference,
        hits_by_record: vec![],
        verifiable: None,
        warnings: vec![],
        errors: vec![api_error],
        debug_info: None,
    };

    json_api_response(status_code, api_response)
}
