// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, HashSet};

use crate::cookie::SessionCookie;
use crate::nonce::ServerNonce;
use crate::types::OpenRequest;
use certificates::{ExemptionTokenGroup, Id, Signature, TokenBundle};
use shared_types::et::WithOtps;
use shared_types::hash::HashSpec;

#[derive(Debug, Clone)]
pub struct InitializedClientState {
    pub open_request: OpenRequest,
    /// The last server_version seen from this server, if known.
    pub last_server_version: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct OpenedClientState {
    pub client_mutual_auth_sig: Signature,
    pub hash_spec: HashSpec,
    pub server_version: u64,
}

/// Small wrapper for handling client session logic.
#[derive(Debug)]
pub struct ServerSessions<State>(HashMap<SessionCookie, State>);

impl<State> ServerSessions<State> {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Add a new client session, if one does not already exist for this cookie.
    ///
    /// If a state already exists for this cookie, it will be returned as an Err, and
    /// the new state will not be inserted.
    pub fn add_session(&mut self, cookie: SessionCookie, state: State) -> Result<(), &State> {
        use std::collections::hash_map::Entry;

        match self.0.entry(cookie) {
            Entry::Occupied(_) => Err(self.0.get(&cookie).unwrap()),
            Entry::Vacant(v) => {
                v.insert(state);
                Ok(())
            }
        }
    }

    /// Take a session from the session map, leaving that space empty so that another request
    /// can't be made with it until the step is finished and the session is readded.
    pub fn take_session(&mut self, cookie: &SessionCookie) -> Option<State> {
        self.0.remove(cookie)
    }
}

impl<T> Default for ServerSessions<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A struct the server must store, keyed by Ncookie
#[derive(Debug)]
pub enum ServerStateForClient {
    Opened(ServerStateForOpenedClient),
    Authenticated(ServerStateForAuthenticatedClient),
}

#[derive(Debug)]
pub struct ServerStateForOpenedClient {
    pub cookie: SessionCookie,
    pub open_request: OpenRequest,
    pub server_nonce: ServerNonce,
}

#[derive(Debug)]
pub enum EtState {
    /// This client is not using exemptions (regular `screen` endpoint).
    NoEt,
    /// This client is screening with exemptions, but has not hit
    /// `screen-with-exemption` yet to tell us the size.
    AwaitingEtSize,
    /// The client has promised to send exemption tokens of the given total size.
    PromisedEt { et_size: u64 },
    /// The client has sent exemption tokens, but some of them contain raw sequences, so we
    /// are waiting for them to hit `exemption-seq-hashes`.
    EtNeedsHashes {
        ets: Vec<WithOtps<TokenBundle<ExemptionTokenGroup>>>,
    },
    /// The client has sent all exemption token data, and we are ready for `exemption-screen-hashes`.
    ///
    /// This can mean that there were no raw sequences (in which case `hashes` is empty)
    /// or the hashes for raw sequences have been received (via `exemption-seq-hashes`).
    EtReady {
        ets: Vec<WithOtps<TokenBundle<ExemptionTokenGroup>>>,
        hashes: HashSet<[u8; 32]>,
    },
}

#[derive(Debug)]
pub struct ServerStateForAuthenticatedClient {
    pub cookie: SessionCookie,
    pub open_request: OpenRequest,
    pub server_nonce: ServerNonce,
    pub hash_total_count: u64,
    pub et_state: EtState,
}

impl ServerStateForClient {
    pub fn cookie(&self) -> SessionCookie {
        match self {
            ServerStateForClient::Opened(ServerStateForOpenedClient { cookie, .. })
            | ServerStateForClient::Authenticated(ServerStateForAuthenticatedClient {
                cookie,
                ..
            }) => *cookie,
        }
    }

    pub fn open_request(&self) -> &OpenRequest {
        match self {
            ServerStateForClient::Opened(ServerStateForOpenedClient { open_request, .. })
            | ServerStateForClient::Authenticated(ServerStateForAuthenticatedClient {
                open_request,
                ..
            }) => open_request,
        }
    }

    /// Unique id from client machine certificate
    pub fn client_mid(&self) -> Id {
        self.open_request().client_mid()
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn server_sessions_double_add() {
        let cookie: SessionCookie = rand::thread_rng().gen();
        let mut sessions = ServerSessions::<u8>::new();
        sessions.add_session(cookie, 1).unwrap();
        assert_eq!(sessions.add_session(cookie, 2).unwrap_err(), &1);
    }

    #[test]
    fn server_sessions_double_take() {
        let cookie: SessionCookie = rand::thread_rng().gen();
        let mut sessions = ServerSessions::<u8>::new();
        sessions.add_session(cookie, 1).unwrap();
        assert_eq!(sessions.take_session(&cookie).unwrap(), 1);
        assert_eq!(sessions.take_session(&cookie), None);
    }
}
