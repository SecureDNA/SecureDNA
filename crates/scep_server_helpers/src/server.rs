// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::future::Future;

use certificates::{
    key_traits::CanLoadKey, KeyPair, PublicKey, SynthesizerTokenGroup, TokenBundle, TokenGroup,
};
use hyper::{body::Incoming, Request, StatusCode};
use minhttp::response::GenericResponse;
use shared_types::hash::HashSpec;
use tokio::sync::RwLock;
use tracing::info;

use scep::states::{ServerSessions, ServerStateForClient};

pub struct ServerState<T: TokenGroup> {
    pub clients: RwLock<ServerSessions<ServerStateForClient>>,
    pub json_size_limit: u64,
    pub manufacturer_roots: Vec<PublicKey>,
    pub token_bundle: TokenBundle<T>,
    pub keypair: KeyPair,
    /// Do not set the `secure` flag on session cookies, so they can be transported over http://
    /// Useful for local testing.
    pub allow_insecure_cookie: bool,
}

pub async fn scep_endpoint_open<
    T,
    GetClientVersion,
    GetClientVersionFut,
    RecordOpenEvent,
    RecordOpenEventFut,
>(
    server_state: &ServerState<T>,
    server_version: u64,
    hash_spec: &HashSpec,
    get_last_client_version: GetClientVersion,
    record_open_event: RecordOpenEvent,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerPrevalidation>>
where
    T: TokenGroup + Clone + std::fmt::Debug,
    T::Token: CanLoadKey + Clone + std::fmt::Debug,
    T::AssociatedRole: std::fmt::Debug,
    T::ChainType: std::fmt::Debug,
    GetClientVersion: FnOnce(certificates::Id) -> GetClientVersionFut,
    GetClientVersionFut: Future<Output = Option<u64>>,
    RecordOpenEvent: FnOnce(TokenBundle<SynthesizerTokenGroup>, u64) -> RecordOpenEventFut,
    RecordOpenEventFut: Future<Output = ()>,
{
    let body =
        crate::request::check_and_extract_json_body(server_state.json_size_limit, request).await?;
    let open_request = crate::request::parse_json_body(&body)?;

    let (response, client_state) = scep::steps::server_prevalidate_and_mutual_auth::<T, _, _>(
        open_request,
        get_last_client_version,
        &server_state.manufacturer_roots,
        server_version,
        server_state.token_bundle.clone(),
        server_state.keypair.clone(),
        hash_spec.clone(),
    )
    .await?;

    info!(
        "Opening session for client with version_hint={}",
        client_state.open_request().version_hint
    );

    let session_cookie = client_state.cookie();
    let token_bundle = client_state.open_request().cert_chain.clone();
    let protocol_version = client_state.open_request().protocol_version;

    server_state
        .clients
        .write()
        .await
        .add_session(session_cookie, client_state)
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "already had session for generated cookie {session_cookie}"
            ))
        })?;

    record_open_event(token_bundle, protocol_version).await;

    let mut response =
        minhttp::response::json(StatusCode::OK, serde_json::to_string(&response).unwrap());
    response.headers_mut().append(
        hyper::header::SET_COOKIE,
        session_cookie
            .to_http_cookie(server_state.allow_insecure_cookie)
            .to_string()
            .parse()
            .unwrap(),
    );
    Ok(response)
}

pub async fn scep_endpoint_authenticate<
    T,
    GetScreenedLastDay,
    GetScreenedLastDayFut,
    RecordExceedance,
    RecordExceedanceFut,
>(
    server_state: &ServerState<T>,
    server_version: u64,
    get_client_screened_last_day: GetScreenedLastDay,
    record_rate_limit_exceedance: RecordExceedance,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ServerAuthentication>>
where
    T: TokenGroup,
    GetScreenedLastDay: FnOnce(certificates::Id) -> GetScreenedLastDayFut,
    GetScreenedLastDayFut: Future<Output = Result<u64, anyhow::Error>>,
    RecordExceedance: FnOnce(certificates::Id, u64) -> RecordExceedanceFut,
    RecordExceedanceFut: Future<Output = ()>,
{
    // delay warning about the cookie until we know the client is even speaking the right protocol
    // (we don't want logspam from bots)
    let cookie = crate::request::get_session_cookie(request.headers());
    let body =
        crate::request::check_and_extract_json_body(server_state.json_size_limit, request).await?;
    let cookie = cookie?;

    let authenticate_request = crate::request::parse_json_body(&body)?;

    let client_state = server_state
        .clients
        .write()
        .await
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let client_state = scep::steps::server_authenticate_client(
        authenticate_request,
        client_state,
        server_version,
        get_client_screened_last_day,
        record_rate_limit_exceedance,
    )
    .await?;

    let session_cookie = client_state.cookie();

    server_state
        .clients
        .write()
        .await
        .add_session(session_cookie, client_state)
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "duplicate session for authenticated cookie {session_cookie}"
            ))
        })?;

    Ok(minhttp::response::json(StatusCode::OK, "{}"))
}
