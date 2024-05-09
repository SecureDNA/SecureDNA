// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Debug;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::Context;
use bytes::{Buf, Bytes, BytesMut};
use futures::stream::iter as to_stream;
use futures::{StreamExt, TryStream, TryStreamExt};
use hdb::Exemptions;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{HeaderValue, CONTENT_TYPE, SET_COOKIE};
use hyper::{Method, Request, Response, StatusCode};
use scep::steps::{server_elt_client, server_elt_seq_hashes_client};
use scep::types::ScreenWithElParams;
use tokio::net::TcpListener;
use tracing::{error, info};

use certificates::{key_traits::CanLoadKey, KeyPair, PublicKey, TokenBundle, TokenGroup};
use doprf::prf::{CompletedHashValue, HashPart, Query};
use doprf::tagged::TaggedHash;
use minhttp::nursery::Nursery;
use minhttp::response::{self, GenericResponse};
use minhttp::server::Server;
use minhttp::signal::{fast_shutdown_requested, graceful_shutdown_requested};
use scep::states::{ServerSessions, ServerStateForClient};
use shared_types::hash::HashSpec;
use shared_types::requests::RequestId;
use streamed_ristretto::hyper::{check_content_length, from_request, BodyStream};
use streamed_ristretto::stream::{
    check_content_type, ConversionError, HasShortErrorMsg, RistrettoError, HASH_SIZE,
};
use streamed_ristretto::util::chunked;
use streamed_ristretto::HasContentType;

use crate::mock_screening::mock_screen;

const SERVER_VERSION: u64 = 1;

pub struct Opts<T: TokenGroup> {
    pub issuer_pks: Vec<PublicKey>,
    pub server_cert_chain: TokenBundle<T>,
    pub server_keypair: KeyPair,
    pub keyserve_fn: Arc<dyn Fn(Query) -> HashPart + Send + Sync + 'static>,
    pub hash_spec: HashSpec,
}

struct ServerState<T: TokenGroup> {
    clients: RwLock<ServerSessions<ServerStateForClient>>,
    opts: Opts<T>,
}

pub trait KeyserveFn: Fn(Query) -> HashPart + Send + Sync + 'static {}

pub struct TestServer {
    server_port: u16,
    stop_server: Arc<tokio::sync::Notify>,
    server_task_nursery: Nursery,
}

impl TestServer {
    pub async fn spawn<T>(
        opts: Opts<T>,
        post_setup_hook: impl Future<Output = ()> + Send + 'static,
    ) -> Self
    where
        T: TokenGroup + Clone + Debug + Send + Sync + 'static,
        T::Token: CanLoadKey + Clone + Debug + Send + Sync,
        T::AssociatedRole: Debug + Send + Sync,
        T::ChainType: Debug + Send + Sync,
    {
        let (listener, server_port) = make_listener_on_free_port([0, 0, 0, 0]).await;

        // signal to start once server is done setting up
        let finished_setup = Arc::new(tokio::sync::Notify::new());
        // signal server to stop once tests are done
        let stop_server = Arc::new(tokio::sync::Notify::new());

        let server_task_nursery = {
            let mut server_task_nursery = minhttp::nursery::Nursery::new();
            let finished_setup = finished_setup.clone();
            let stop_server = stop_server.clone();
            tokio::spawn(server_task_nursery.chaperone(async move {
                run_server(
                    opts,
                    listener,
                    async {
                        post_setup_hook.await;
                        finished_setup.notify_one();
                    },
                    async {
                        stop_server.notified().await;
                    },
                )
                .await
                .unwrap()
            }));
            server_task_nursery
        };

        // wait for server to finish starting
        finished_setup.notified().await;

        Self {
            server_port,
            stop_server,
            server_task_nursery,
        }
    }

    pub async fn stop(self) {
        info!("stopping server...");
        self.stop_server.notify_one();
        self.server_task_nursery.finish().await;
    }

    pub fn port(&self) -> u16 {
        self.server_port
    }
}

/// Bind a tokio TcpListener on a free port (using the :0 method) and return it,
/// along with the port that was bound.
async fn make_listener_on_free_port(ip_addr: impl Into<IpAddr>) -> (TcpListener, u16) {
    let listener = TcpListener::bind(SocketAddr::from((ip_addr, 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

async fn run_server<T>(
    opts: Opts<T>,
    listener: TcpListener,
    post_setup_hook: impl Future<Output = ()>,
    stop_server: impl Future<Output = ()>,
) -> std::io::Result<()>
where
    T: TokenGroup + Clone + Debug + Send + Sync + 'static,
    T::Token: CanLoadKey + Clone + Debug + Send + Sync,
    T::AssociatedRole: Debug + Send + Sync,
    T::ChainType: Debug + Send + Sync,
{
    let server_state = Arc::new(ServerState {
        clients: RwLock::new(ServerSessions::new()),
        opts,
    });

    let server = Server::new(1_000);

    info!("Listening on {}", listener.local_addr().unwrap());
    let connections = futures::stream::unfold(listener, |listener| async {
        Some((listener.accept().await, listener))
    });

    let run = server
        .with_callbacks()
        .respond(move |request, peer| {
            let server_state = server_state.clone();
            let request_id = RequestId::from(request.headers());
            async move { respond(server_state.clone(), &request_id, peer, request).await }
        })
        .connected(|c| info!("connection from {c}"))
        .failed(move |c| error!("connection failed: {c}"))
        .serve(connections);

    let graceful_shutdown = async {
        graceful_shutdown_requested().await;
        info!("Graceful shutdown requested...");
        server.graceful_shutdown().await;
    };

    // Note: Monitoring plane comes first to prioritize handling its traffic.
    let run_until_gracefully_shutdown = async { tokio::join!(run, graceful_shutdown) };
    post_setup_hook.await;
    tokio::select! {
        biased;
        _ = fast_shutdown_requested() => info!("Fast shutdown requested..."),
        _ = stop_server => info!("Server stopped..."),
        _ = run_until_gracefully_shutdown => {},
    };

    Ok(())
}

async fn respond<T>(
    server_state: Arc<ServerState<T>>,
    request_id: &RequestId,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> GenericResponse
where
    T: TokenGroup + Clone + Debug,
    T::Token: CanLoadKey + Clone + Debug,
    T::AssociatedRole: Debug,
    T::ChainType: Debug,
{
    info!("{request_id}: got request");

    fn ok_or_err<I: std::error::Error>(
        r: Result<GenericResponse, scep::error::ScepError<I>>,
        request_id: &RequestId,
        peer: SocketAddr,
    ) -> GenericResponse {
        match r {
            Ok(r) => r,
            Err(e) => {
                scep_server_helpers::log_and_convert_scep_error_to_response(&e, request_id, peer).0
            }
        }
    }

    match (request.method(), request.uri().path()) {
        (&Method::POST, scep::OPEN_ENDPOINT) => ok_or_err(
            endpoint_open(request_id, &server_state, request).await,
            request_id,
            peer,
        ),
        (&Method::OPTIONS, scep::OPEN_ENDPOINT) => response::empty(),
        (&Method::POST, scep::AUTHENTICATE_ENDPOINT) => ok_or_err(
            endpoint_authenticate(request_id, &server_state, request).await,
            request_id,
            peer,
        ),
        (&Method::OPTIONS, scep::AUTHENTICATE_ENDPOINT) => response::empty(),
        (&Method::POST, scep::KEYSERVE_ENDPOINT) => ok_or_err(
            endpoint_keyserve(request_id, &server_state, request).await,
            request_id,
            peer,
        ),
        (&Method::OPTIONS, scep::KEYSERVE_ENDPOINT) => response::empty(),
        (&Method::POST, scep::SCREEN_ENDPOINT | scep::ELT_SCREEN_HASHES_ENDPOINT) => ok_or_err(
            endpoint_screen(request_id, &server_state, request).await,
            request_id,
            peer,
        ),
        (&Method::OPTIONS, scep::SCREEN_ENDPOINT | scep::ELT_SCREEN_HASHES_ENDPOINT) => {
            response::empty()
        }
        (&Method::POST, scep::SCREEN_WITH_EL_ENDPOINT) => ok_or_err(
            endpoint_screen_with_el(request_id, &server_state, request).await,
            request_id,
            peer,
        ),
        (&Method::OPTIONS, scep::SCREEN_WITH_EL_ENDPOINT) => response::empty(),
        (&Method::POST, scep::ELT_ENDPOINT) => ok_or_err(
            endpoint_elt(request_id, &server_state, request).await,
            request_id,
            peer,
        ),
        (&Method::OPTIONS, scep::ELT_ENDPOINT) => response::empty(),
        (&Method::POST, scep::ELT_SEQ_HASHES_ENDPOINT) => ok_or_err(
            endpoint_elt_seq_hashes(request_id, &server_state, request).await,
            request_id,
            peer,
        ),
        (&Method::OPTIONS, scep::ELT_SEQ_HASHES_ENDPOINT) => response::empty(),
        _ => response::not_found(),
    }
}

async fn endpoint_open<T>(
    _request_id: &RequestId,
    server_state: &ServerState<T>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerPrevalidation>>
where
    T: TokenGroup + Clone + Debug,
    T::Token: CanLoadKey + Clone + Debug,
    T::AssociatedRole: Clone + Debug,
    T::ChainType: Clone + Debug,
{
    let body = scep_server_helpers::request::check_and_extract_json_body(100_000, request).await?;
    let open_request = scep_server_helpers::request::parse_json_body(&body)?;

    let (response, client_state) = scep::steps::server_prevalidate_and_mutual_auth::<T, _, _>(
        open_request,
        |_| async { None },
        &server_state.opts.issuer_pks,
        SERVER_VERSION,
        server_state.opts.server_cert_chain.clone(),
        server_state.opts.server_keypair.clone(),
        server_state.opts.hash_spec.clone(),
    )
    .await?;

    let session_cookie = client_state.cookie();

    server_state
        .clients
        .write()
        .unwrap()
        .add_session(session_cookie, client_state)
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "already had session for generated cookie {session_cookie}"
            ))
        })?;

    let mut response = response::json(StatusCode::OK, serde_json::to_string(&response).unwrap());
    response.headers_mut().append(
        SET_COOKIE,
        session_cookie
            .to_http_cookie(true)
            .to_string()
            .parse()
            .unwrap(),
    );
    Ok(response)
}

async fn endpoint_authenticate<T: TokenGroup>(
    _request_id: &RequestId,
    server_state: &ServerState<T>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerAuthentication>> {
    // delay warning about the cookie until we know the client is even speaking the right protocol
    // (we don't want logspam from bots)
    let cookie = scep_server_helpers::request::get_session_cookie(request.headers());
    let body = scep_server_helpers::request::check_and_extract_json_body(100_000, request).await?;
    let cookie = cookie?;

    let authenticate_request = scep_server_helpers::request::parse_json_body(&body)?;

    let client_state = server_state
        .clients
        .write()
        .unwrap()
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let client_state = scep::steps::server_authenticate_client(
        authenticate_request,
        client_state,
        SERVER_VERSION,
        |_| async { Ok(0) },
        |_, _| async {},
    )
    .await?;

    let session_cookie = client_state.cookie();

    server_state
        .clients
        .write()
        .unwrap()
        .add_session(session_cookie, client_state)
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "duplicate session for authenticated cookie {session_cookie}"
            ))
        })?;

    Ok(response::json(StatusCode::OK, "{}"))
}

async fn endpoint_keyserve<T: TokenGroup>(
    request_id: &RequestId,
    server_state: &ServerState<T>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::Keyserve>> {
    check_content_type(request.headers(), Query::CONTENT_TYPE)
        .context("in keyserve")
        .map_err(scep::error::ScepError::InvalidMessage)?;

    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = server_state
        .clients
        .write()
        .unwrap()
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let hash_count_from_content_len =
        check_content_length(request.body().size_hint().exact(), HASH_SIZE)
            .context("in keyserve")
            .map_err(scep::error::ScepError::InvalidMessage)?;
    scep::steps::server_keyserve_client(hash_count_from_content_len, client_state)?;

    info!("{request_id}: Processing request of size {hash_count_from_content_len}");

    let chunks = map_ristretto_stream(
        BodyStream(request.into_body()),
        server_state.opts.keyserve_fn.clone(),
    );

    let body = StreamBody::new(chunks.map_ok(Frame::data));
    let mut response = Response::new(body);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(HashPart::CONTENT_TYPE),
    );
    let response = response.map(|body| BodyExt::map_err(body, anyhow::Error::from).boxed());
    Ok(response)
}

async fn endpoint_screen<T: TokenGroup>(
    request_id: &RequestId,
    server_state: &ServerState<T>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::Screen>> {
    check_content_type(request.headers(), TaggedHash::CONTENT_TYPE)
        .context("in screen")
        .map_err(scep::error::ScepError::InvalidMessage)?;

    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = server_state
        .clients
        .write()
        .unwrap()
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let hash_count_from_content_len =
        check_content_length(request.body().size_hint().exact(), TaggedHash::SIZE)
            .context("in screen")
            .map_err(scep::error::ScepError::InvalidMessage)?;

    info!("{request_id}: Screening request of size {hash_count_from_content_len}");

    let (_common, client) =
        scep::steps::server_screen_client(hash_count_from_content_len, client_state)?;

    let hashes: Vec<TaggedHash> = from_request(request).unwrap().try_collect().await.unwrap();
    let exemptions = match client.elt_state {
        scep::states::EltState::NoElt => Default::default(),
        scep::states::EltState::EltReady { elt, hashes, .. } => {
            Exemptions::new_unchecked(vec![*elt], hashes)
        }
        _ => panic!("bad ELT state in SCEP integration test"),
    };

    info!("Got hashes: {hashes:?}");

    Ok(response::json(
        StatusCode::OK,
        serde_json::to_string_pretty(&mock_screen(&hashes, &exemptions)).unwrap(),
    ))
}

async fn endpoint_screen_with_el<T: TokenGroup>(
    request_id: &RequestId,
    server_state: &ServerState<T>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ScreenWithEL>> {
    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = server_state
        .clients
        .write()
        .unwrap()
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let bytes = request
        .into_body()
        .collect()
        .await
        .map_err(|e| scep::error::ScepError::InvalidMessage(e.into()))?
        .to_bytes();

    let params: ScreenWithElParams = serde_json::from_slice(&bytes)
        .map_err(|e| scep::error::ScepError::InvalidMessage(e.into()))?;

    info!("{request_id}: screen-with-EL, params {params:?}");

    let new_client_state = scep::steps::server_screen_with_el_client(params, client_state)?;

    server_state
        .clients
        .write()
        .unwrap()
        .add_session(
            cookie,
            ServerStateForClient::Authenticated(new_client_state),
        )
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "failed to update state for cookie {cookie}"
            ))
        })?;

    Ok(response::json(StatusCode::OK, "{}"))
}

async fn endpoint_elt<T: TokenGroup>(
    request_id: &RequestId,
    server_state: &ServerState<T>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ELT>> {
    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = server_state
        .clients
        .write()
        .unwrap()
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let elt_body = request
        .into_body()
        .collect()
        .await
        .map_err(|e| scep::error::ScepError::InvalidMessage(e.into()))?
        .to_bytes();

    info!("{request_id}: ELT, body {} bytes", elt_body.len());

    let (client, response) = server_elt_client(elt_body, client_state)?;

    server_state
        .clients
        .write()
        .unwrap()
        .add_session(cookie, ServerStateForClient::Authenticated(client))
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "failed to update state for cookie {cookie}"
            ))
        })?;

    // Give them the OK to hit /ELT-seq-hashes or /ELT-screen-hashes next.
    Ok(response::json(
        StatusCode::OK,
        serde_json::to_string(&response).map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!("failed to encode response JSON"))
        })?,
    ))
}

async fn endpoint_elt_seq_hashes<T: TokenGroup>(
    request_id: &RequestId,
    server_state: &ServerState<T>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::EltSeqHashes>> {
    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = server_state
        .clients
        .write()
        .unwrap()
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let hashes: Vec<_> = from_request::<_, CompletedHashValue>(request)
        .context("in ELT-seq-hashes")
        .map_err(scep::error::ScepError::InvalidMessage)?
        .try_collect()
        .await
        .context("in ELT-seq-hashes")
        .map_err(scep::error::ScepError::InvalidMessage)?;

    info!(
        "{request_id}: ELT-seq-hashes, parsed {} hashes",
        hashes.len()
    );
    let client = server_elt_seq_hashes_client(hashes, client_state)?;

    server_state
        .clients
        .write()
        .unwrap()
        .add_session(cookie, ServerStateForClient::Authenticated(client))
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "failed to update state for cookie {cookie}"
            ))
        })?;

    // Give them the OK to hit /ELT-screen-hashes next.
    Ok(response::json(StatusCode::OK, "{}"))
}

// Given a stream of `Bytes`/errors, interprets them as `Queries` and applies `f` to them
//
// Encodes the resulting `HashPart`s back into Bytes and returns a stream of said `Bytes`/errors.
fn map_ristretto_stream<I>(
    input: I,
    f: Arc<dyn Fn(Query) -> HashPart + Send + Sync + 'static>,
) -> impl TryStream<Ok = Bytes, Error = RistrettoError<I::Error, ConversionError<Query>>>
where
    I: TryStream,
    I::Ok: Buf,
    I::Error: Send + 'static,
{
    let mut output_bufs = BytesMut::new();
    chunked(input, HASH_SIZE)
        .map(move |chunk| {
            let chunk = chunk.map_err(RistrettoError::Stream)?;
            if chunk.len() % HASH_SIZE != 0 {
                return Err(RistrettoError::Incomplete { data: chunk });
            }

            // We split off enough memory to hold a mapped chunk
            // so that map_ristretto_chunk doesn't typically need to allocate anything.
            output_bufs.resize(chunk.len(), 0);
            let mut out_buf = output_bufs.split();
            out_buf.truncate(0);

            let f = f.clone();
            Ok(async move {
                tokio::task::spawn_blocking(move || Ok(map_ristretto_chunk(chunk, out_buf, f)))
                    .await
                    .unwrap()
            })
        })
        .try_buffered(10)
        .try_flatten()
        .flat_map(|chunk| match chunk {
            Ok(buf) => {
                let items = [Ok(buf)];
                to_stream(items).left_stream()
            }
            Err(err) => {
                let mut err_data = vec![255; HASH_SIZE];
                err_data[1..HASH_SIZE - 1].copy_from_slice(&err.short_err_msg());
                let items = [Ok(err_data.into()), Err(err)];
                to_stream(items).right_stream()
            }
        })
}

// Decodes `input` into `Queries`, maps them through `f` and returns a stream of `Bytes` / errors.
//
// `output_buf` is used as a buffer to hold encoded `HashParts` before returning them.
fn map_ristretto_chunk<SE>(
    mut input: Bytes,
    mut output_buf: BytesMut,
    f: Arc<dyn Fn(Query) -> HashPart>,
) -> impl TryStream<Ok = Bytes, Error = RistrettoError<SE, ConversionError<Query>>> {
    while !input.is_empty() {
        let data = input.split_to(HASH_SIZE);
        let data_ref: &[u8; HASH_SIZE] = data.as_ref().try_into().unwrap();
        let query = match data_ref.try_into() {
            Ok(q) => q,
            Err(error) => {
                let items = [
                    Ok(output_buf.freeze()),
                    Err(RistrettoError::Conversion { data, error }),
                ];
                return to_stream(items).left_stream();
            }
        };

        let hash_part: [u8; HASH_SIZE] = f(query).into();
        output_buf.extend_from_slice(&hash_part);
    }

    let items = [Ok(output_buf.freeze())];
    to_stream(items).right_stream()
}
