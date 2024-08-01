// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};

use anyhow::Context;
use bytes::Bytes;
use certificates::{ChainTraversal, ExemptionTokenGroup, TokenBundle};
use futures::future::join_all;
use futures::FutureExt;
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::{HeaderMap, Method, Request, StatusCode, Uri};
use once_cell::sync::Lazy;
use regex::bytes::Regex as BytesRegex;
use serde::de::DeserializeOwned;
use shared_types::error::InvalidClientTokenBundle;
use shared_types::et::WithOtps;
use tokio::sync::Mutex;
use tracing::{error, info};

use doprf::party::KeyserverId;
use doprf_client::server_selection::ServerSelector;
use doprf_client::server_version_handler::LastServerVersionHandler;
use minhttp::error::ErrWrapper;
use minhttp::mpserver::traits::ValidServerSetup;
use minhttp::mpserver::{MultiplaneServer, ServerConfig};
use minhttp::response::{self, GenericResponse};
use quickdna::NucleotideAmbiguous;
use securedna_versioning::version::get_version;
use shared_types::http::add_cors_headers;
use shared_types::metrics::{get_metrics_output, SynthClientMetrics};
use shared_types::requests::RequestId;
use shared_types::server_versions::{HdbVersion, KeyserverVersion};

use crate::api::{
    ApiError, ApiResponse, CheckFastaRequest, CheckNcbiRequest, RequestCommon, SynthesisPermission,
    VersionInfo,
};
use crate::ncbi::download_fasta_by_acc_number;
use crate::parsefasta::{check_fasta, CheckerConfiguration, CurrentSystemLoadTracker};
use crate::rate_limiter::{RateLimiter, SystemTimeHourProvider};

use crate::shims::recaptcha::validate_recaptcha;
use crate::shims::server_selection::initialize_server_selector;
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

    if let Some(limit) = app_cfg.memorylimit {
        info!("Running with memory limit: {limit}B");
    }

    let certs = Arc::new(app_cfg.certs.validate_and_build()?);

    info!("Initializing server selector...");
    let server_selector = initialize_server_selector(&app_cfg).await.unwrap();
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

    fn parse(path: &str) -> Option<Self> {
        match path {
            "/v1/screen" => Some(Self::Fasta),
            "/v1/demo" => Some(Self::FastaDemo),
            "/v1/ncbi" => Some(Self::Ncbi),
            _ => None,
        }
    }
}

async fn respond(
    sc_state: Arc<SynthClientState>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> GenericResponse {
    let method = request.method().clone();
    let headers = request.headers().clone();
    let path = request.uri().path();
    let real_ip = headers
        .get("X-Real-Ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<IpAddr>().ok())
        .unwrap_or(peer.ip());

    let mut response = match (method, ScreenSource::parse(path), path) {
        (Method::OPTIONS, _, _) => response::empty(),
        (Method::GET, _, "/version") => query_server_version(&sc_state).await,
        (Method::GET, _, "/") => index(&sc_state, request),
        (Method::POST, Some(source), _) => {
            let mut provider_reference: Option<String> = None;
            match screen(source, &sc_state, real_ip, request, &mut provider_reference).await {
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

fn index(state: &SynthClientState, request: Request<Incoming>) -> GenericResponse {
    let host = request
        .headers()
        .get(hyper::header::HOST)
        .and_then(|hv| std::str::from_utf8(hv.as_bytes()).ok())
        .map(|host| {
            if state.is_serving_https || forwarded_from_https(request.headers()) {
                format!("https://{host}")
            } else {
                format!("http://{host}")
            }
        });

    if let Some(host) = host {
        let mut url = state.app_cfg.frontend_url.clone();
        url.query_pairs_mut().append_pair("api", host.as_str());
        response::see_other(url.as_str())
    } else {
        response::see_other(state.app_cfg.frontend_url.as_str())
    }
}

async fn screen(
    source: ScreenSource,
    state: &SynthClientState,
    real_ip: IpAddr,
    request: Request<Incoming>,
    out_provider_reference: &mut Option<String>,
) -> Result<ApiResponse, ApiError> {
    let (parts, body) = request.into_parts();
    let body = check_and_extract_json_body(body, state.app_cfg.json_size_limit).await?;

    let _gauge = state.metrics.as_ref().map(|m| m.connected_clients());
    if let Some(m) = state.metrics.as_ref() {
        m.requests.inc();
    }

    let (sequence, common, request_id) = match source {
        ScreenSource::Ncbi => {
            let CheckNcbiRequest { id, common } = serde_json::from_slice(&body)?;
            out_provider_reference.clone_from(&common.provider_reference);
            let request_id = init_request(&common).await;

            info!("{request_id}: begin fetching {id} from NCBI");
            let sequence = download_fasta_by_acc_number(&request_id, id).await?;
            info!(
                "{}: begin checking NCBI FASTA (length {})",
                request_id,
                sequence.len()
            );
            (sequence, common, request_id)
        }
        ScreenSource::Fasta | ScreenSource::FastaDemo => {
            let CheckFastaRequest { fasta, common } = serde_json::from_slice(&body)?;
            out_provider_reference.clone_from(&common.provider_reference);
            let request_id = init_request(&common).await;

            if source == ScreenSource::FastaDemo {
                let client_ip = real_ip;
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
        et.path_to_leaf().map_err(|err| InvalidClientTokenBundle {
            error: err,
            token_kind: certificates::TokenKind::Exemption,
        })?;
    }

    let config = CheckerConfiguration {
        server_selector: Arc::clone(&state.server_selector),
        certs: Arc::clone(&state.certs),
        include_debug_info: debug_info,
        metrics: state.metrics.as_ref().map(Arc::clone),
        region: common.region,
        limit_config: state.limit_config(source.screening_type()),
        use_http: state.app_cfg.use_http,
        provider_reference: common.provider_reference,
        synthclient_version_hint: &state.synthclient_version,
        ets,
        server_version_handler,
    };

    let api_response = check_fasta::<NucleotideAmbiguous>(&request_id, sequence, &config).await?;

    info!(
        "{}: finished, status = {:?}",
        request_id, api_response.synthesis_permission
    );

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
        warnings: vec![],
        errors: vec![api_error],
        debug_info: None,
    };

    json_api_response(status_code, api_response)
}

/// Try to discern whether the user is accessing us from an https url, using the
/// Forwarded, X-Forwarded-Proto(col), and X-Forwarded-SSL headers
fn forwarded_from_https(headers: &HeaderMap) -> bool {
    if let Some(fwd) = headers.get(hyper::header::FORWARDED) {
        static PROTO_HTTPS: Lazy<BytesRegex> =
            Lazy::new(|| BytesRegex::new(r"(?i)proto=https").unwrap());
        PROTO_HTTPS.is_match(fwd.as_bytes())
    } else if let Some(x_fwd_proto) = headers
        .get("x-forwarded-proto")
        .or_else(|| headers.get("x-forwarded-protocol"))
        .or_else(|| headers.get("x-url-scheme"))
    {
        static HTTPS: Lazy<BytesRegex> = Lazy::new(|| BytesRegex::new(r"(?i)https").unwrap());
        HTTPS.is_match(x_fwd_proto.as_bytes())
    } else if let Some(x_fwd_ssl) = headers
        .get("x-forwarded-ssl")
        .or_else(|| headers.get("front-end-https"))
    {
        static ON: Lazy<BytesRegex> = Lazy::new(|| BytesRegex::new(r"(?i)on").unwrap());
        ON.is_match(x_fwd_ssl.as_bytes())
    } else {
        false
    }
}
