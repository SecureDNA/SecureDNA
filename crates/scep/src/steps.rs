// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{cmp::Ordering, collections::HashSet, future::Future};

use anyhow::Context;
use rand::Rng;
use serde::{Deserialize, Serialize};
use shared_types::{
    error::{InvalidClientTokenBundle, InvalidInfrastructureTokenBundle},
    et::WithOtps,
    hash::HashSpec,
};
use tracing::{info, trace};

use super::mutual_authentication;
use crate::{
    error::{self, ScepError},
    nonce::{ClientNonce, ServerNonce},
    states::{
        EtState, InitializedClientState, OpenedClientState, ServerStateForAuthenticatedClient,
        ServerStateForClient, ServerStateForOpenedClient,
    },
    types::{
        AuthenticateRequest, ClientRequestType, OpenRequest, OpenResponse, ScreenCommon,
        ScreenWithExemptionParams,
    },
};
use certificates::revocation::RevocationList;
use certificates::{
    key_traits::{CanLoadKey, HasAssociatedKey, KeyLoaded},
    Infrastructure,
};
use certificates::{
    ChainTraversal, DatabaseTokenGroup, ExemptionTokenGroup, Issued, KeyPair, KeyserverTokenGroup,
    PublicKey, SynthesizerTokenGroup, TokenBundle, TokenGroup,
};
use doprf::{
    party::{KeyserverId, KeyserverIdSet},
    prf::CompletedHashValue,
};

pub fn client_initialize(
    request_type: ClientRequestType,
    version_hint: String,
    cert_chain: TokenBundle<SynthesizerTokenGroup>,
    nucleotide_total_count: u64,
    last_server_version: Option<u64>,
    keyserver_id_set: KeyserverIdSet,
    debug_info: bool,
) -> (OpenRequest, InitializedClientState) {
    let client_nonce: ClientNonce = rand::thread_rng().gen();

    let request = OpenRequest {
        protocol_version: 1,
        version_hint,
        nonce: client_nonce,
        request_type,
        cert_chain: cert_chain.clone(),
        nucleotide_total_count,
        keyserver_id_set,
        debug_info,
    };

    let client_state = InitializedClientState {
        open_request: request.clone(),
        last_server_version,
    };

    (request, client_state)
}

pub async fn server_prevalidate_and_mutual_auth<
    ServerTokenKind,
    GetLastClientVersion,
    GetLastClientVersionFut,
>(
    request: serde_json::Value,
    get_last_client_version: GetLastClientVersion,
    issuer_pks: &[PublicKey],
    server_version: u64,
    server_cert_chain: TokenBundle<ServerTokenKind>,
    server_keypair: KeyPair,
    hash_spec: HashSpec,
) -> Result<
    (OpenResponse<ServerTokenKind>, ServerStateForClient),
    ScepError<error::ServerPrevalidation>,
>
where
    ServerTokenKind: TokenGroup + std::fmt::Debug,
    ServerTokenKind::Token: CanLoadKey + Clone + std::fmt::Debug,
    ServerTokenKind::AssociatedRole: std::fmt::Debug,
    ServerTokenKind::ChainType: std::fmt::Debug,
    GetLastClientVersion: FnOnce(certificates::Id) -> GetLastClientVersionFut,
    GetLastClientVersionFut: Future<Output = Option<u64>>,
{
    // check version *before* we try to parse as something specific
    let protocol_version = request
        .get("protocol_version")
        .and_then(|v| v.as_u64())
        .ok_or(ScepError::BadProtocol)?;
    match protocol_version.cmp(&1) {
        Ordering::Less => return Err(error::ServerPrevalidation::ClientVersionTooLow.into()),
        Ordering::Greater => return Err(error::ServerPrevalidation::ClientVersionTooHigh.into()),
        _ => {}
    };

    // now we can deserialize and provide error diagnostics
    let request: OpenRequest = serde_json::value::from_value(request)
        .context("while parsing request")
        .map_err(ScepError::InvalidMessage)?;

    if let Some(last_client_version) = get_last_client_version(request.client_mid()).await {
        if protocol_version < last_client_version {
            return Err(error::ServerPrevalidation::VersionRollback.into());
        }
    }

    // check cert has a valid root path
    // DO NOT check if cert is revoked yet!
    request
        .cert_chain
        .validate_path_to_issuers(issuer_pks, None)
        .map_err(|error| {
            error::ServerPrevalidation::InvalidCert(InvalidClientTokenBundle {
                error,
                token_kind: certificates::TokenKind::Synthesizer,
            })
        })?;

    // TODO: check NTC (what does that entail?)

    // check keyserver id set
    if !keyserver_id_set_valid(&request.keyserver_id_set) {
        return Err(ScepError::InvalidMessage(anyhow::anyhow!(
            "keyserver id set {:?} is invalid",
            request.keyserver_id_set
        )));
    }

    // generate the server nonce
    let server_nonce: ServerNonce = rand::thread_rng().gen();

    // generate and sign the mutual authentication string
    let server_mutual_auth = mutual_authentication::generate_server_mutual_auth(
        (server_version, server_nonce),
        (request.protocol_version, request.nonce),
        &server_cert_chain,
    )
    .context("while generating server mutual auth string")
    .map_err(ScepError::InternalError)?;

    trace!("server cert chain {:?}", server_cert_chain);
    trace!("server mutual auth on server: {}", server_mutual_auth);

    let server_mutual_auth_sig = server_cert_chain
        .token
        .clone()
        .load_key(server_keypair)
        .context("while loading server keypair")
        .map_err(ScepError::InternalError)?
        .sign(server_mutual_auth.as_ref());

    let response = OpenResponse {
        server_version,
        nonce: server_nonce,
        cert_chain: server_cert_chain,
        sig: server_mutual_auth_sig,
        hash_spec,
    };
    let client_state = ServerStateForClient::Opened(ServerStateForOpenedClient {
        cookie: rand::thread_rng().gen(),
        open_request: request,
        server_nonce,
    });
    Ok((response, client_state))
}

fn client_prevalidate_and_mutual_auth<ServerTokenKind>(
    open_response: serde_json::Value,
    client_state: InitializedClientState,
    client_keypair: KeyPair,
    issuer_pks: &[PublicKey],
    server_specific_validation: impl FnOnce(
        &OpenResponse<ServerTokenKind>,
    ) -> Result<(), ScepError<error::ClientPrevalidation>>,
) -> Result<OpenedClientState, ScepError<error::ClientPrevalidation>>
where
    ServerTokenKind: TokenGroup<AssociatedRole = Infrastructure> + std::fmt::Debug,
    ServerTokenKind::Token: CanLoadKey + std::fmt::Debug,
    ServerTokenKind::ChainType: std::fmt::Debug,
{
    // check version *before* we try to parse as something specific
    let server_version = open_response
        .get("server_version")
        .and_then(|v| v.as_u64())
        .ok_or(ScepError::BadProtocol)?;

    // we don't need to check if the server version is supported yet, since we
    // only have one kind of server right now.
    // later, we may need to reject servers that are too old.
    // we NEVER will reject servers that are too new—that's the server's job.
    // if the server understands our protocol version, it isn't too new.

    if let Some(last_server_version) = client_state.last_server_version {
        if server_version < last_server_version {
            return Err(error::ClientPrevalidation::VersionRollback.into());
        }
    }

    // now we can deserialize
    let open_response: OpenResponse<ServerTokenKind> = serde_json::value::from_value(open_response)
        .context("while parsing the server response")
        .map_err(ScepError::InvalidMessage)?;

    // We verify the cert has a valid path to root but intentionally delay checking
    // for revocations until we know the client possesses the appropriate private key,
    // in order to avoid leaking revocations to random unauthenticated strangers.
    open_response
        .cert_chain
        .validate_path_to_issuers(issuer_pks, None)
        .map_err(|error| {
            error::ClientPrevalidation::InvalidCert(InvalidInfrastructureTokenBundle {
                error,
                token_kind: ServerTokenKind::token_kind(),
                roots: issuer_pks.to_vec(),
            })
        })?;

    // check that server mutual auth is valid
    let server_mutual_auth = mutual_authentication::generate_server_mutual_auth(
        (open_response.server_version, open_response.nonce),
        (
            client_state.open_request.protocol_version,
            client_state.open_request.nonce,
        ),
        &open_response.cert_chain,
    )
    .context("while generating server mutual auth string")
    .map_err(ScepError::InternalError)?;

    trace!("open response cert chain {:?}", open_response.cert_chain);
    trace!("server mutual auth on client: {}", server_mutual_auth);

    open_response
        .cert_chain
        .token
        .verify(server_mutual_auth.as_ref(), &open_response.sig)?;

    // TODO: validate HTD entries

    let client_mutual_auth = mutual_authentication::generate_client_mutual_auth(
        (open_response.server_version, open_response.nonce),
        (
            client_state.open_request.protocol_version,
            client_state.open_request.nonce,
        ),
        &client_state.open_request.cert_chain,
    )
    .context("while generating client mutual auth string")
    .map_err(ScepError::InternalError)?;

    let client_mutual_auth_sig = client_state
        .open_request
        .cert_chain
        .token
        .load_key(client_keypair)
        .context("while loading client keypair")
        .map_err(ScepError::InternalError)?
        .sign(client_mutual_auth.as_ref());

    server_specific_validation(&open_response)?;

    Ok(OpenedClientState {
        client_mutual_auth_sig,
        hash_spec: open_response.hash_spec,
        server_version: open_response.server_version,
    })
}

pub fn client_prevalidate_and_mutual_auth_keyserver(
    open_response: serde_json::Value,
    client_state: InitializedClientState,
    client_keypair: KeyPair,
    issuer_pks: &[PublicKey],
    expected_keyserver_id: KeyserverId,
) -> Result<OpenedClientState, ScepError<error::ClientPrevalidation>> {
    client_prevalidate_and_mutual_auth::<KeyserverTokenGroup>(
        open_response,
        client_state,
        client_keypair,
        issuer_pks,
        |open_response| {
            let id = *open_response.cert_chain.token.keyserver_id();
            if id != expected_keyserver_id {
                Err(ScepError::Inner(
                    error::ClientPrevalidation::InvalidKeyserverId {
                        expected: expected_keyserver_id,
                        in_cert: id,
                    },
                ))
            } else {
                Ok(())
            }
        },
    )
}

pub fn client_prevalidate_and_mutual_auth_hdb(
    open_response: serde_json::Value,
    client_state: InitializedClientState,
    client_keypair: KeyPair,
    issuer_pks: &[PublicKey],
) -> Result<OpenedClientState, ScepError<error::ClientPrevalidation>> {
    client_prevalidate_and_mutual_auth::<DatabaseTokenGroup>(
        open_response,
        client_state,
        client_keypair,
        issuer_pks,
        |_| Ok(()),
    )
}

pub fn client_authenticate(state: OpenedClientState, hash_total_count: u64) -> AuthenticateRequest {
    AuthenticateRequest {
        sig: state.client_mutual_auth_sig,
        hash_total_count,
    }
}

pub async fn server_authenticate_client<
    GetScreenedLastDay,
    GetScreenedLastDayFut,
    RecordExceedance,
    RecordExceedanceFut,
>(
    authenticate_request: serde_json::Value,
    client_state: ServerStateForClient,
    server_version: u64,
    issuer_pks: &[PublicKey],
    revocation_list: &RevocationList,
    get_client_screened_last_day: GetScreenedLastDay,
    record_rate_limit_exceedance: RecordExceedance,
) -> Result<ServerStateForClient, ScepError<error::ServerAuthentication>>
where
    GetScreenedLastDay: FnOnce(certificates::Id) -> GetScreenedLastDayFut,
    GetScreenedLastDayFut: Future<Output = Result<u64, anyhow::Error>>,
    RecordExceedance: FnOnce(certificates::Id, u64) -> RecordExceedanceFut,
    RecordExceedanceFut: Future<Output = ()>,
{
    let client_state = match client_state {
        ServerStateForClient::Opened(client_state) => client_state,
        ServerStateForClient::Authenticated(_) => {
            return Err(error::ServerAuthentication::ClientAlreadyAuthenticated.into());
        }
    };
    // TODO: do we need to check cookie validity from the state? like a timeout

    // right now we just deserialize this, but later we might need to use the saved `protocol_version`
    // to deserialize it appropriately
    // TODO: log error better more info etc
    let authenticate_request: AuthenticateRequest =
        serde_json::value::from_value(authenticate_request)
            .context("while parsing request")
            .map_err(ScepError::InvalidMessage)?;

    // check client mutual auth signature
    let client_mutual_auth = mutual_authentication::generate_client_mutual_auth(
        (server_version, client_state.server_nonce),
        (
            client_state.open_request.protocol_version,
            client_state.open_request.nonce,
        ),
        &client_state.open_request.cert_chain,
    )
    .context("while generating client mutual auth string")
    .map_err(ScepError::InternalError)?;

    client_state
        .open_request
        .cert_chain
        .token
        .verify(client_mutual_auth.as_ref(), &authenticate_request.sig)?;

    // Check cert has a valid root path while taking revoked certs into account; note that it's
    // important to only do this AFTER authentication, to avoid acting as a revocation oracle.
    client_state
        .open_request
        .cert_chain
        .validate_path_to_issuers(issuer_pks, Some(revocation_list))
        .map_err(|error| {
            error::ServerAuthentication::RevokedCert(InvalidClientTokenBundle {
                error,
                token_kind: certificates::TokenKind::Synthesizer,
            })
        })?;

    if client_htc_unreasonable(
        authenticate_request.hash_total_count,
        client_state.open_request.nucleotide_total_count,
    ) {
        return Err(error::ServerAuthentication::HtcUnreasonable {
            hash_total_count: authenticate_request.hash_total_count,
            nucleotide_total_count: client_state.open_request.nucleotide_total_count,
        }
        .into());
    }

    // check rate limits
    let client_mid = client_state.open_request.client_mid();
    let limit_bp = client_state
        .open_request
        .cert_chain
        .token
        .max_dna_base_pairs_per_day();
    let screened_last_day_bp = get_client_screened_last_day(client_mid)
        .await
        .map_err(|e| {
            ScepError::InternalError(
                e.context(format!("getting bp screened in last day for {client_mid}")),
            )
        })?;
    let attempted_bp = client_state.open_request.nucleotide_total_count;

    if screened_last_day_bp.saturating_add(attempted_bp) >= limit_bp {
        info!(
            message = "rate_limit_exceedance",
            %client_mid,
            issued_to=client_state.open_request.cert_chain.token.issuer_description(),
            limit_bp,
            screened_last_day_bp,
            attempted_bp
        );
        record_rate_limit_exceedance(client_mid, attempted_bp).await;
        Err(ScepError::RateLimitExceeded { limit_bp })
    } else {
        let et_state = match &client_state.open_request.request_type {
            ClientRequestType::ScreenWithExemption(_) => EtState::AwaitingEtSize,
            _ => EtState::NoEt,
        };
        Ok(ServerStateForClient::Authenticated(
            ServerStateForAuthenticatedClient {
                cookie: client_state.cookie,
                open_request: client_state.open_request,
                server_nonce: client_state.server_nonce,
                hash_total_count: authenticate_request.hash_total_count,
                et_state,
            },
        ))
    }
}

pub fn client_validate_authenticate_response(
    authenticate_response: serde_json::Value,
) -> Result<(), ScepError<error::ClientPrevalidation>> {
    if !authenticate_response.is_object() {
        Err(ScepError::InvalidMessage(anyhow::anyhow!(
            "expected JSON object (possibly empty), got {authenticate_response:?}"
        )))
    } else {
        Ok(())
    }
}

pub fn server_keyserve_client(
    hash_count_from_content_len: u64,
    client_state: ServerStateForClient,
) -> Result<KeyserverIdSet, ScepError<error::Keyserve>> {
    let client_state = match client_state {
        ServerStateForClient::Opened(_) => {
            return Err(error::Keyserve::ClientNotAuthenticated.into());
        }
        ServerStateForClient::Authenticated(state) => state,
    };

    if client_state.open_request.request_type != ClientRequestType::Keyserve {
        return Err(
            error::Keyserve::WrongRequestType(client_state.open_request.request_type).into(),
        );
    }

    if hash_count_from_content_len > client_state.hash_total_count {
        return Err(error::Keyserve::TooManyHashes {
            requested: client_state.hash_total_count,
            provided: hash_count_from_content_len,
        }
        .into());
    }

    Ok(client_state.open_request.keyserver_id_set)
}

/// Code for the `screen` and `exemption-screen-hashes` endpoints.
pub fn server_screen_client(
    hash_count_from_content_len: u64,
    client_state: ServerStateForClient,
) -> Result<(ScreenCommon, ServerStateForAuthenticatedClient), ScepError<error::Screen>> {
    let client_state = match client_state {
        ServerStateForClient::Opened(_) => {
            return Err(error::Screen::ClientNotAuthenticated.into());
        }
        ServerStateForClient::Authenticated(state) => state,
    };

    let params = match (
        &client_state.open_request.request_type,
        &client_state.et_state,
    ) {
        (ClientRequestType::Screen(params), EtState::NoEt) => params.clone(),
        (ClientRequestType::ScreenWithExemption(params), EtState::EtReady { .. }) => params.clone(),
        (ClientRequestType::ScreenWithExemption(_), EtState::EtNeedsHashes { .. }) => {
            return Err(error::Screen::ScreenBeforeEtHashes.into())
        }
        (ClientRequestType::ScreenWithExemption(_), _) => {
            return Err(error::Screen::ScreenBeforeEt.into())
        }
        (request_type, _) => {
            return Err(error::Screen::WrongRequestType(request_type.clone()).into())
        }
    };

    if hash_count_from_content_len > client_state.hash_total_count {
        return Err(error::Screen::TooManyHashes {
            requested: client_state.hash_total_count,
            provided: hash_count_from_content_len,
        }
        .into());
    }

    Ok((params, client_state))
}

/// Code for the `screen-with-exemption` endpoint.
pub fn server_screen_with_el_client(
    params: ScreenWithExemptionParams,
    client_state: ServerStateForClient,
) -> Result<ServerStateForAuthenticatedClient, ScepError<error::ScreenWithEL>> {
    let ServerStateForClient::Authenticated(mut client_state) = client_state else {
        return Err(error::ScreenWithEL::ClientNotAuthenticated.into());
    };

    if !matches!(
        &client_state.open_request.request_type,
        ClientRequestType::ScreenWithExemption { .. }
    ) {
        return Err(
            error::ScreenWithEL::WrongRequestType(client_state.open_request.request_type).into(),
        );
    }

    match &client_state.et_state {
        EtState::AwaitingEtSize => {
            client_state.et_state = EtState::PromisedEt {
                et_size: params.et_size,
            };
        }
        EtState::NoEt
        | EtState::PromisedEt { .. }
        | EtState::EtNeedsHashes { .. }
        | EtState::EtReady { .. } => return Err(error::ScreenWithEL::WrongEtState.into()),
    };

    Ok(client_state)
}

#[derive(Serialize, Deserialize)]
pub struct EtEndpointResponse {
    pub needs_hashes: bool,
}

/// Code for the `exemption` endpoint.
pub fn server_et_client(
    et_body: bytes::Bytes,
    client_state: ServerStateForClient,
) -> Result<(ServerStateForAuthenticatedClient, EtEndpointResponse), ScepError<error::ET>> {
    let ServerStateForClient::Authenticated(mut client) = client_state else {
        return Err(error::ET::ClientNotAuthenticated.into());
    };

    let EtState::PromisedEt { et_size } = client.et_state else {
        return Err(error::ET::WrongEtState.into());
    };

    if Ok(et_size) != et_body.len().try_into() {
        return Err(error::ET::SizeMismatch.into());
    }

    let ets: Vec<WithOtps<String>> =
        serde_json::from_slice(&et_body).map_err(error::ET::JsonDecodeError)?;

    type Et = WithOtps<TokenBundle<ExemptionTokenGroup>>;
    let ets: Result<Vec<Et>, _> = ets
        .iter()
        .map(|et| et.clone().try_map(TokenBundle::from_file_contents))
        .collect();
    let ets = ets.map_err(error::ET::PemDecodeError)?;

    let needs_hashes = ets.iter().any(|et| et.et.token.has_dna_sequences());
    client.et_state = if needs_hashes {
        EtState::EtNeedsHashes { ets }
    } else {
        EtState::EtReady {
            ets,
            hashes: Default::default(),
        }
    };

    let response = EtEndpointResponse { needs_hashes };
    Ok((client, response))
}

/// Code for the `exemption-seq-hashes` endpoint.
pub fn server_et_seq_hashes_client(
    hashes: impl IntoIterator<Item = CompletedHashValue>,
    client_state: ServerStateForClient,
) -> Result<ServerStateForAuthenticatedClient, ScepError<error::EtSeqHashes>> {
    let ServerStateForClient::Authenticated(mut client) = client_state else {
        return Err(error::EtSeqHashes::ClientNotAuthenticated.into());
    };

    let EtState::EtNeedsHashes { ets } = client.et_state else {
        return Err(error::EtSeqHashes::WrongEtState.into());
    };

    let hashes: HashSet<[u8; 32]> = hashes.into_iter().map(Into::into).collect();

    client.et_state = EtState::EtReady { ets, hashes };

    Ok(client)
}

fn client_htc_unreasonable(_hash_total_count: u64, _nucleotide_total_count: u64) -> bool {
    false // TODO
}

fn keyserver_id_set_valid(keyserver_id_set: &KeyserverIdSet) -> bool {
    let mut last: Option<KeyserverId> = None;
    for item in keyserver_id_set.iter() {
        if let Some(last) = last {
            if item.as_u32() <= last.as_u32() {
                return false; // no duplicates, must be sorted
            }
        }
        last = Some(*item);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_keyserver_id_set_valid() {
        macro_rules! assert_validity {
            ($validity:expr, $($x:expr),*) => {
                if keyserver_id_set_valid(
                    &KeyserverIdSet::from_iter([$(KeyserverId::try_from($x).unwrap()),*]),
                ) != $validity {
                    panic!(
                        "[{}] should be {}!",
                        stringify!($($x),*),
                        if $validity { "valid" } else { "invalid" },
                    );
                }
            }
        }
        assert_validity!(true, 1, 2, 3);
        assert_validity!(true, 3, 5, 9);
        assert_validity!(true, 1, 9);
        assert_validity!(false, 1, 2, 2, 3);
    }
}
