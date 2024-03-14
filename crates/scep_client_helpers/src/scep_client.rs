// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use crate::ClientCerts;
use certificates::{
    CanLoadKey, DatabaseTokenGroup, KeyPair, KeyserverTokenGroup, PublicKey, TokenGroup,
};
use doprf::{
    party::{KeyserverId, KeyserverIdSet},
    prf::{HashPart, Query},
    tagged::TaggedHash,
};
use http_client::{BaseApiClient, HTTPError};
use packed_ristretto::PackedRistrettos;
use scep::{
    states::{InitializedClientState, OpenedClientState},
    types::{ClientRequestType, ScreenCommon},
};
use shared_types::{hdb::HdbScreeningResult, synthesis_permission::Region};

pub struct ScepClient<ServerTokenKind> {
    api_client: BaseApiClient,
    domain: String,
    certs: Arc<ClientCerts>,
    version_hint: String,
    _phantom: std::marker::PhantomData<ServerTokenKind>,
}

impl<ServerTokenKind> ScepClient<ServerTokenKind>
where
    ServerTokenKind: TokenGroup + std::fmt::Debug,
    ServerTokenKind::Token: CanLoadKey + std::fmt::Debug,
    ServerTokenKind::AssociatedRole: std::fmt::Debug,
{
    pub fn new(
        api_client: BaseApiClient,
        domain: String,
        certs: Arc<ClientCerts>,
        version_hint: String,
    ) -> Self {
        Self {
            api_client,
            domain,
            certs,
            version_hint,
            _phantom: Default::default(),
        }
    }

    async fn generic_open(
        &self,
        request_type: ClientRequestType,
        nucleotide_total_count: u64,
        last_server_version: Option<u64>,
        keyserver_id_set: KeyserverIdSet,
        prevalidate_fn: impl FnOnce(
            serde_json::Value,
            InitializedClientState,
            KeyPair,
            &[PublicKey],
        ) -> Result<
            OpenedClientState,
            scep::error::ScepError<scep::error::ClientPrevalidation>,
        >,
    ) -> Result<OpenedClientState, Error<scep::error::ClientPrevalidation>> {
        let (open_request, client_state) = scep::steps::client_initialize(
            request_type,
            self.version_hint.clone(),
            self.certs.token.clone(),
            nucleotide_total_count,
            last_server_version,
            keyserver_id_set,
        );

        let open_response: serde_json::Value = self
            .api_client
            .json_json_post(
                &format!("{}{}", self.domain, scep::OPEN_ENDPOINT),
                &open_request,
            )
            .await?;

        let opened_client = prevalidate_fn(
            open_response,
            client_state,
            self.certs.keypair.clone(),
            &self.certs.issuer_pks[..],
        )
        .map_err(|source| Error::Scep {
            source,
            domain: self.domain.clone(),
        })?;

        Ok(opened_client)
    }

    pub async fn authenticate(
        &self,
        opened_client: OpenedClientState,
        hash_total_count: u64,
    ) -> Result<(), Error<scep::error::ClientPrevalidation>> {
        let authenticate_request =
            scep::steps::client_authenticate(opened_client, hash_total_count);

        let response: serde_json::Value = self
            .api_client
            .json_json_post(
                &format!("{}{}", self.domain, scep::AUTHENTICATE_ENDPOINT),
                &authenticate_request,
            )
            .await?;

        scep::steps::client_validate_authenticate_response(response).map_err(|source| Error::Scep {
            source,
            domain: self.domain.clone(),
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl ScepClient<KeyserverTokenGroup> {
    pub async fn open(
        &self,
        nucleotide_total_count: u64,
        last_server_version: Option<u64>,
        keyserver_id_set: KeyserverIdSet,
        expected_keyserver_id: KeyserverId,
    ) -> Result<OpenedClientState, Error<scep::error::ClientPrevalidation>> {
        self.generic_open(
            ClientRequestType::Keyserve,
            nucleotide_total_count,
            last_server_version,
            keyserver_id_set,
            |open_response: serde_json::Value,
             client_state: InitializedClientState,
             client_keypair: KeyPair,
             issuer_pks: &[PublicKey]| {
                scep::steps::client_prevalidate_and_mutual_auth_keyserver(
                    open_response,
                    client_state,
                    client_keypair,
                    issuer_pks,
                    expected_keyserver_id,
                )
            },
        )
        .await
    }

    pub async fn keyserve(
        &self,
        queries: &PackedRistrettos<Query>,
    ) -> Result<PackedRistrettos<HashPart>, HTTPError> {
        self.api_client
            .ristretto_ristretto_post(
                &format!("{}{}", self.domain, scep::KEYSERVE_ENDPOINT),
                queries,
            )
            .await
    }
}

impl ScepClient<DatabaseTokenGroup> {
    pub async fn open(
        &self,
        nucleotide_total_count: u64,
        last_server_version: Option<u64>,
        keyserver_id_set: KeyserverIdSet,
        region: Region,
    ) -> Result<OpenedClientState, Error<scep::error::ClientPrevalidation>> {
        self.generic_open(
            ClientRequestType::Screen(ScreenCommon {
                region,
                provider_reference: None,
            }),
            nucleotide_total_count,
            last_server_version,
            keyserver_id_set,
            scep::steps::client_prevalidate_and_mutual_auth_hdb,
        )
        .await
    }

    pub async fn screen(
        &self,
        hashes: &PackedRistrettos<TaggedHash>,
    ) -> Result<HdbScreeningResult, HTTPError> {
        self.api_client
            .ristretto_json_post(&format!("{}{}", self.domain, scep::SCREEN_ENDPOINT), hashes)
            .await
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error<E: std::error::Error> {
    #[error("during scep for {domain}: {source}")]
    Scep {
        source: scep::error::ScepError<E>,
        domain: String,
    },
    #[error("{0}")]
    Http(#[from] HTTPError),
}
