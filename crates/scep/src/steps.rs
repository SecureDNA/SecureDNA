// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{cmp::Ordering, future::Future};

use anyhow::Context;
use rand::Rng;
use shared_types::hash::HashSpec;
use tracing::trace;

use super::mutual_authentication;
use crate::{
    error::{self, ScepError},
    nonce::{ClientNonce, ServerNonce},
    states::{
        InitializedClientState, OpenedClientState, ServerStateForAuthenticatedClient,
        ServerStateForClient, ServerStateForOpenedClient,
    },
    types::{AuthenticateRequest, ClientRequestType, OpenRequest, OpenResponse, ScreenCommon},
};
use certificates::{
    CanLoadKey, ChainTraversal, DatabaseTokenGroup, HasAssociatedKey, KeyLoaded, KeyPair,
    KeyserverTokenGroup, PublicKey, SynthesizerTokenGroup, TokenBundle, TokenGroup,
};
use doprf::party::{KeyserverId, KeyserverIdSet};

pub fn client_initialize(
    request_type: ClientRequestType,
    version_hint: String,
    cert_chain: TokenBundle<SynthesizerTokenGroup>,
    nucleotide_total_count: u64,
    last_server_version: Option<u64>,
    keyserver_id_set: KeyserverIdSet,
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
    if request
        .cert_chain
        .validate_path_to_issuers(issuer_pks)
        .is_err()
    {
        return Err(error::ServerPrevalidation::InvalidCert.into());
    }

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
    ServerTokenKind: TokenGroup + std::fmt::Debug,
    ServerTokenKind::Token: CanLoadKey + std::fmt::Debug,
    ServerTokenKind::AssociatedRole: std::fmt::Debug,
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

    // check cert has a valid root path
    // DO NOT check if cert is revoked yet!
    if open_response
        .cert_chain
        .validate_path_to_issuers(issuer_pks)
        .is_err()
    {
        return Err(error::ClientPrevalidation::InvalidCert.into());
    }

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
    get_client_screened_last_day: GetScreenedLastDay,
    record_rate_limit_exceedance: RecordExceedance,
) -> Result<ServerStateForClient, ScepError<error::ServerAuthentication>>
where
    GetScreenedLastDay: FnOnce(certificates::Id) -> GetScreenedLastDayFut,
    GetScreenedLastDayFut: Future<Output = Result<u64, anyhow::Error>>,
    RecordExceedance: FnOnce(TokenBundle<SynthesizerTokenGroup>, u64) -> RecordExceedanceFut,
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

    let screened_last_day = get_client_screened_last_day(client_mid)
        .await
        .map_err(|e| {
            ScepError::InternalError(
                e.context(format!("getting bp screened in last day for {client_mid}")),
            )
        })?;

    if screened_last_day.saturating_add(client_state.open_request.nucleotide_total_count)
        >= limit_bp
    {
        record_rate_limit_exceedance(
            // would like to avoid clone here but async closures don't play nice with references
            client_state.open_request.cert_chain.clone(),
            client_state.open_request.nucleotide_total_count,
        )
        .await;
        Err(ScepError::RateLimitExceeded { limit_bp })
    } else {
        Ok(ServerStateForClient::Authenticated(
            ServerStateForAuthenticatedClient {
                cookie: client_state.cookie,
                open_request: client_state.open_request,
                server_nonce: client_state.server_nonce,
                hash_total_count: authenticate_request.hash_total_count,
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

    let params = match client_state.open_request.request_type {
        ClientRequestType::Screen(ref params) => params.clone(),
        t => return Err(error::Screen::WrongRequestType(t).into()),
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
