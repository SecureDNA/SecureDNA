// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use crate::ClientCerts;
use certificates::key_traits::CanLoadKey;
use certificates::{
    DatabaseTokenGroup, ExemptionTokenGroup, KeyPair, KeyserverTokenGroup, PublicKey, TokenBundle,
    TokenGroup,
};
use doprf::prf::CompletedHashValue;
use doprf::{
    party::{KeyserverId, KeyserverIdSet},
    prf::{HashPart, Query},
    tagged::TaggedHash,
};
use http_client::{BaseApiClient, HttpError};
use packed_ristretto::PackedRistrettos;
use scep::steps::EtEndpointResponse;
use scep::types::ScreenWithExemptionParams;
use scep::{
    states::{InitializedClientState, OpenedClientState},
    types::{ClientRequestType, ScreenCommon},
};
use shared_types::et::WithOtps;
use shared_types::{hdb::HdbScreeningResult, synthesis_permission::Region};

pub struct ScepClient<ServerTokenKind> {
    api_client: BaseApiClient,
    domain: String,
    certs: Arc<ClientCerts>,
    version_hint: String,
    snoop_open_response: Option<SnoopFn>,
    snoop_auth_response: Option<SnoopFn>,
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
            snoop_open_response: None,
            snoop_auth_response: None,
            _phantom: Default::default(),
        }
    }

    /// Set hooks for snooping on the (unvalidated) open / authentication responses.
    ///
    /// If you wait until after open / authenticate return Ok(...) to use these snooped
    /// values, they will have been parsed and validated for correctness.
    pub fn snoop(mut self, snoop_open_response: SnoopFn, snoop_auth_response: SnoopFn) -> Self {
        self.snoop_open_response = Some(snoop_open_response);
        self.snoop_auth_response = Some(snoop_auth_response);
        self
    }

    async fn generic_open(
        &self,
        request_type: ClientRequestType,
        nucleotide_total_count: u64,
        last_server_version: Option<u64>,
        keyserver_id_set: KeyserverIdSet,
        debug_info: bool,
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
            debug_info,
        );

        let open_response: serde_json::Value = self
            .api_client
            .json_json_post(
                &format!("{}{}", self.domain, scep::OPEN_ENDPOINT),
                &open_request,
            )
            .await?;

        if let Some(snoop_open_response) = &self.snoop_open_response {
            snoop_open_response(&open_response);
        }

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

        if let Some(snoop_auth_response) = &self.snoop_auth_response {
            snoop_auth_response(&response);
        }

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
        debug_info: bool,
    ) -> Result<OpenedClientState, Error<scep::error::ClientPrevalidation>> {
        self.generic_open(
            ClientRequestType::Keyserve,
            nucleotide_total_count,
            last_server_version,
            keyserver_id_set,
            debug_info,
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
    ) -> Result<PackedRistrettos<HashPart>, HttpError> {
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
        debug_info: bool,
        region: Region,
        with_exemption: bool,
    ) -> Result<OpenedClientState, Error<scep::error::ClientPrevalidation>> {
        let common = ScreenCommon {
            region,
            provider_reference: None,
        };
        let request_type = if with_exemption {
            ClientRequestType::ScreenWithExemption(common)
        } else {
            ClientRequestType::Screen(common)
        };
        self.generic_open(
            request_type,
            nucleotide_total_count,
            last_server_version,
            keyserver_id_set,
            debug_info,
            scep::steps::client_prevalidate_and_mutual_auth_hdb,
        )
        .await
    }

    pub async fn screen(
        &self,
        hashes: &PackedRistrettos<TaggedHash>,
    ) -> Result<HdbScreeningResult, HttpError> {
        self.api_client
            .ristretto_json_post(&format!("{}{}", self.domain, scep::SCREEN_ENDPOINT), hashes)
            .await
    }

    pub async fn screen_with_ets(
        &self,
        hashes: &PackedRistrettos<TaggedHash>,
        ets: &[WithOtps<TokenBundle<ExemptionTokenGroup>>],
        et_hashes: &PackedRistrettos<CompletedHashValue>,
    ) -> Result<HdbScreeningResult, HttpError> {
        let et_pems: Result<Vec<_>, _> = ets
            .iter()
            .map(|w| w.as_ref().try_map(|e| e.to_file_contents()))
            .collect();
        let et_pems = et_pems.map_err(|e| HttpError::EncodeError {
            encoding: "exemption token".to_owned(),
            source: e.into(),
        })?;
        let et_wire: Vec<u8> =
            serde_json::to_vec(&et_pems).map_err(|e| HttpError::EncodeError {
                encoding: "exemption token".to_owned(),
                source: e.into(),
            })?;

        self.api_client
            .json_json_post::<_, serde_json::Value>(
                &format!("{}{}", self.domain, scep::SCREEN_WITH_EXEMPTION_ENDPOINT),
                &ScreenWithExemptionParams {
                    et_size: et_wire.len().try_into().unwrap_or(u64::MAX),
                },
            )
            .await?;
        let response: EtEndpointResponse = self
            .api_client
            .bytes_json_post(
                &format!("{}{}", self.domain, scep::EXEMPTION_ENDPOINT),
                et_wire.into(),
                "application/json",
            )
            .await?;

        let has_dna = ets.iter().any(|w| w.et.token.has_dna_sequences());
        if response.needs_hashes && !has_dna {
            return Err(HttpError::ProtocolError {
                error: "Server says we need to send hashes but our exemption tokens have no DNA sequences."
                    .to_owned(),
            });
        }

        if !response.needs_hashes && has_dna {
            return Err(HttpError::ProtocolError {
                error: "Server says we don't need to send hashes, but our exemption tokens have DNA sequences."
                    .to_owned(),
            });
        }

        if response.needs_hashes {
            self.api_client
                .ristretto_json_post::<_, serde_json::Value>(
                    &format!("{}{}", self.domain, scep::EXEMPTION_SEQ_HASHES_ENDPOINT),
                    et_hashes,
                )
                .await?;
        }
        self.api_client
            .ristretto_json_post(
                &format!("{}{}", self.domain, scep::EXEMPTION_SCREEN_HASHES_ENDPOINT),
                hashes,
            )
            .await
    }
}

pub type SnoopFn = Box<dyn Fn(&serde_json::Value) + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum Error<E: std::error::Error> {
    #[error("during scep for {domain}: {source}")]
    Scep {
        source: scep::error::ScepError<E>,
        domain: String,
    },
    #[error("{0}")]
    Http(#[from] HttpError),
}
