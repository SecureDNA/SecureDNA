// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use certificates::TokenBundle;
use futures::future::join_all;
use futures::FutureExt;
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::{HeaderMap, Method, Request, StatusCode, Uri};
use once_cell::sync::Lazy;
use regex::bytes::Regex as BytesRegex;
use serde::de::DeserializeOwned;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, info_span, Instrument};

use doprf::party::KeyserverId;
use doprf_client::server_selection::ServerSelector;
use doprf_client::server_version_handler::LastServerVersionHandler;
use minhttp::response::{self, GenericResponse};
use minhttp::server::Server;
use minhttp::signal::{fast_shutdown_requested, graceful_shutdown_requested};
use quickdna::NucleotideAmbiguous;
use securedna_versioning::version::get_version;
use shared_types::http::add_cors_headers;
use shared_types::info_with_timestamp;
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
use crate::shims::types::{Opts, SynthClientState};

use super::types::ScreeningType;

pub async fn run(opts: Opts, post_setup_hook: impl Future<Output = ()>) -> anyhow::Result<()> {
    if let Some(limit) = opts.memorylimit {
        info_with_timestamp!("Running with memory limit: {}B", limit);
    }

    let certs = Arc::new(opts.certs.validate_and_build()?);

    info_with_timestamp!("Initializing server selector...");
    let server_selector = initialize_server_selector(&opts).await.unwrap();
    info_with_timestamp!("Finished initializing server selector");
    let metrics = if !opts.disable_statistics {
        let m = SynthClientMetrics::default();
        let max_clients: i64 = opts.max_clients.try_into().unwrap();
        m.max_clients.set(max_clients);
        Some(Arc::new(m))
    } else {
        None
    };

    let limits = CurrentSystemLoadTracker {
        current_base_pair_counter: AtomicUsize::new(0),
    };

    let rate_limiter = Mutex::new(RateLimiter::<IpAddr, _>::new(
        opts.recaptcha_requests_per_hour,
        SystemTimeHourProvider,
    ));

    let server = Server::new(opts.max_clients);
    // Note: Separate server so regular connections don't count against the monitoring plane limit.
    let monitoring_plane_server = Server::new(opts.max_monitoring_plane_clients);

    let address = SocketAddr::from(([0, 0, 0, 0], opts.port));
    info!("Listening on {address}");
    let listener = TcpListener::bind(address)
        .await
        .map_err(|err| PortAdvice::new(opts.port, err))
        .with_context(|| format!("Couldn't listen on port {}.", opts.port))?;
    let connections = futures::stream::unfold(listener, |listener| async {
        Some((listener.accept().await, listener))
    });

    let run_monitoring_plane = if let Some(port) = opts.monitoring_plane_port {
        let address = SocketAddr::from(([0, 0, 0, 0], port));
        info!("Listening on {address} for monitoring plane");
        let listener = TcpListener::bind(address)
            .await
            .map_err(|err| PortAdvice::new(port, err))
            .with_context(|| format!("Couldn't listen on port {port} for monitoring plane."))?;
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

    let synthclient_version = securedna_versioning::version::get_version();

    let persistence_connection = Arc::new(
        crate::shims::event_store::open_db(&opts.event_store_path)
            .await
            .context("opening event store db")?,
    );

    let sc_state = Arc::new(SynthClientState {
        opts,
        server_selector: Arc::new(server_selector),
        metrics: metrics.clone(),
        limits,
        demo_rate_limiter: rate_limiter,
        certs,
        synthclient_version,
        persistence_connection,
    });

    // let metrics2 = metrics.clone();
    let run = server
        .with_callbacks()
        .respond(move |request, peer| {
            let sc_state = sc_state.clone();
            async move { respond(sc_state.clone(), peer, request).await }
        })
        .connected(|_| metrics.as_ref().map(|m| m.connected_clients()))
        .failed(move |_| {
            // synthclient doesn't count bad requests
            // if let Some(m) = metrics2 {
            //     m.bad_requests.inc();
            // }
        })
        .serve(connections);

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

    let mut response = match (method, ScreenSource::parse(path), path) {
        (Method::OPTIONS, _, _) => response::empty(),
        (Method::GET, _, "/version") => query_server_version(&sc_state).await,
        (Method::GET, _, "/") => index(&sc_state, request),
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

/// Uses the common request fields to validate the API key, generate a RequestId, and
/// log the request_id / provider_reference so they can be correlated.
async fn init_request(common: &RequestCommon) -> RequestId {
    let request_id = RequestId::new_unique();

    // TODO: this should be associated with the request tracing span eventually,
    //       but we haven't gotten tracing working yet
    info_with_timestamp!(
        "{}: validated request with provider_reference={:?} and region={:?}",
        request_id,
        common.provider_reference,
        common.region
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
            if forwarded_from_https(request.headers()) {
                format!("https://{host}")
            } else {
                format!("http://{host}")
            }
        });

    if let Some(host) = host {
        let mut url = state.opts.frontend_url.clone();
        url.query_pairs_mut().append_pair("api", host.as_str());
        response::see_other(url.as_str())
    } else {
        response::see_other(state.opts.frontend_url.as_str())
    }
}

async fn screen(
    source: ScreenSource,
    state: &SynthClientState,
    peer: SocketAddr,
    request: Request<Incoming>,
    out_provider_reference: &mut Option<String>,
) -> Result<ApiResponse, ApiError> {
    let (parts, body) = request.into_parts();
    let body = check_and_extract_json_body(body, state.opts.json_size_limit).await?;

    let _gauge = state.metrics.as_ref().map(|m| m.connected_clients());
    if let Some(m) = state.metrics.as_ref() {
        m.requests.inc();
    }

    let (sequence, common, request_id) = match source {
        ScreenSource::Ncbi => {
            let CheckNcbiRequest { id, common } = serde_json::from_slice(&body)?;
            *out_provider_reference = common.provider_reference.clone();
            let request_id = init_request(&common).await;

            info_with_timestamp!("{}: begin fetching {} from NCBI", request_id, id);
            let sequence = download_fasta_by_acc_number(&request_id, id).await?;
            info_with_timestamp!(
                "{}: begin checking NCBI FASTA (length {})",
                request_id,
                sequence.len()
            );
            (sequence, common, request_id)
        }
        ScreenSource::Fasta | ScreenSource::FastaDemo => {
            let CheckFastaRequest { fasta, common } = serde_json::from_slice(&body)?;
            *out_provider_reference = common.provider_reference.clone();
            let request_id = init_request(&common).await;

            if source == ScreenSource::FastaDemo {
                let client_ip = peer.ip();
                let recaptcha_token = str_param(&parts.uri, "recaptcha_token").unwrap_or_default();

                info_with_timestamp!(
                    "{}: screen ({:?}) client_ip={}, recaptcha_token={}",
                    request_id,
                    source,
                    client_ip,
                    recaptcha_token
                );

                let secret = state.opts.recaptcha_secret_key.as_deref();
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

    let elt = match common.elt_pem {
        None => None,
        Some(pem) => Some(TokenBundle::from_file_contents(pem)?),
    };

    let config = CheckerConfiguration {
        server_selector: Arc::clone(&state.server_selector),
        certs: Arc::clone(&state.certs),
        include_debug_info: debug_info,
        metrics: state.metrics.as_ref().map(Arc::clone),
        region: common.region,
        limit_config: state.limit_config(source.screening_type()),
        use_http: state.opts.use_http,
        provider_reference: common.provider_reference,
        synthclient_version_hint: &state.synthclient_version,
        elt,
        otp: common.otp,
        server_version_handler,
    };

    let api_response = check_fasta::<NucleotideAmbiguous>(&request_id, sequence, &config).await?;

    info_with_timestamp!(
        "{}: finished, status = {:?}",
        request_id,
        api_response.synthesis_permission
    );

    Ok(api_response)
}

async fn query_server_version(state: &SynthClientState) -> GenericResponse {
    let synthclient_version = get_version();
    let hdb_version = get_hdb_version(state.server_selector.clone(), state.opts.use_http).await;
    let (hdbserver_version, hdb_timestamp) = match hdb_version {
        Some(v) => (Some(v.server_version), v.hdb_timestamp),
        None => (None, None),
    };
    let keyserver_versions =
        get_keyserver_versions(state.server_selector.clone(), state.opts.use_http).await;

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
        .map_err(|err| info_with_timestamp!("error when getting {}: {}", url, err))
        .ok()?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| info_with_timestamp!("error when getting text from {}: {}", url, err))
        .ok()?;

    if status != reqwest::StatusCode::OK {
        info_with_timestamp!("{} returned non-200 response: {}", url, text);
        return None;
    }
    match serde_json::from_str(&text) {
        Ok(hdb_version) => Some(hdb_version),
        Err(err) => {
            info_with_timestamp!(
                "{} returned unparsesable response: {} (from {:?})",
                url,
                err,
                text
            );
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

#[derive(Debug)]
struct PortAdvice {
    port: u16,
    inner: std::io::Error,
}

impl PortAdvice {
    fn new(port: u16, inner: std::io::Error) -> Self {
        Self { port, inner }
    }
}

impl std::error::Error for PortAdvice {}

impl std::fmt::Display for PortAdvice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.inner.fmt(f)?;
        if self.inner.kind() == std::io::ErrorKind::PermissionDenied && self.port < 1024 {
            write!(f, "\n(ports under 1024 usually require admin privileges)")?;
        }
        Ok(())
    }
}
