// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ops::Deref;
use std::sync::Arc;

use bytes::Bytes;
use futures::{Stream, TryStream, TryStreamExt};

use crate::ClientCerts;
use certificates::key_traits::CanLoadSigningKey;
use certificates::{
    DatabaseTokenGroup, ExemptionTokenGroup, KeyserverTokenGroup, PublicKey, SigningKeyPair,
    TokenBundle, TokenGroup,
};
use doprf::{
    party::{KeyserverId, KeyserverIdSet},
    prf::{CompressedCompletedHashValue, CompressedHashPart, CompressedQuery},
    tagged::TaggedHash,
};
use hdb_api::HdbScreeningResult;
use http_client::body::zerocopy::{StreamChunk, Streamed};
use http_client::body::{Json, TryIntoBody};
use http_client::service::util::{add_header, BoxedError};
use http_client::{BaseApiClient, HttpError};
use packed_ristretto::{PackableRistretto, PackedRistrettos};
use scep::cookie::SessionCookie;
use scep::steps::EtEndpointResponse;
use scep::types::{ScreenWithExemptionParams, VerifiableScreeningRequested};
use scep::{
    states::{InitializedClientState, OpenedClientState},
    types::{ClientRequestType, ScreenCommon},
};
use shared_types::et::WithOtps;
use shared_types::synthesis_permission::Region;

pub struct ScepClient<ServerTokenKind> {
    api_client: BaseApiClient,
    domain: String,
    certs: Arc<ClientCerts>,
    version_hint: String,
    snoop_open_response: Option<SnoopFn>,
    snoop_auth_response: Option<SnoopFn>,
    _phantom: std::marker::PhantomData<ServerTokenKind>,
}

#[derive(Clone)]
pub struct ScepClientOpenCommon {
    pub nucleotide_total_count: u64,
    pub last_server_version: Option<u64>,
    pub keyserver_id_set: KeyserverIdSet,
    pub debug_info: bool,
}

impl<ServerTokenKind> ScepClient<ServerTokenKind>
where
    ServerTokenKind: TokenGroup + std::fmt::Debug,
    ServerTokenKind::Token: CanLoadSigningKey + std::fmt::Debug,
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
        common: ScepClientOpenCommon,
        prevalidate_fn: impl FnOnce(
            serde_json::Value,
            InitializedClientState,
            SigningKeyPair,
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
            common.nucleotide_total_count,
            common.last_server_version,
            common.keyserver_id_set,
            common.debug_info,
        );

        let url = format!("{}{}", self.domain, scep::OPEN_ENDPOINT);
        let Json(open_response) = self.api_client.post(url, Json(&open_request)).await?;

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
    ) -> Result<SessionCookie, Error<scep::error::ClientPrevalidation>> {
        let session_id = opened_client.session_id;
        let api_client = add_session(&self.api_client, session_id);

        let url = format!("{}{}", self.domain, scep::AUTHENTICATE_ENDPOINT);
        let auth_request = scep::steps::client_authenticate(opened_client, hash_total_count);
        let Json(response) = api_client.post(url, Json(&auth_request)).await?;

        if let Some(snoop_auth_response) = &self.snoop_auth_response {
            snoop_auth_response(&response);
        }

        scep::steps::client_validate_authenticate_response(response).map_err(|source| {
            Error::Scep {
                source,
                domain: self.domain.clone(),
            }
        })?;

        Ok(session_id)
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl ScepClient<KeyserverTokenGroup> {
    pub async fn open(
        &self,
        common: ScepClientOpenCommon,
        expected_keyserver_id: KeyserverId,
    ) -> Result<OpenedClientState, Error<scep::error::ClientPrevalidation>> {
        self.generic_open(
            ClientRequestType::Keyserve,
            common,
            |open_response: serde_json::Value,
             client_state: InitializedClientState,
             client_keypair: SigningKeyPair,
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

    // Backwards-compat shim so existing tests are exercising the `keyserve_stream` code.
    pub async fn keyserve(
        &self,
        session_id: SessionCookie,
        queries: &PackedRistrettos<CompressedQuery>,
    ) -> Result<PackedRistrettos<CompressedHashPart>, HttpError> {
        let (total_queries, queries) = packed_to_len_and_stream(queries, "queries")?;
        let hashpart_chunks = self
            .keyserve_stream(session_id, total_queries, queries)
            .await?;
        let hashparts = hashpart_chunks
            .map_ok(|chunk| futures::stream::iter(chunk.map(Ok)))
            .try_flatten();
        hashparts.try_collect().await
    }

    pub async fn keyserve_stream<Q>(
        &self,
        session_id: SessionCookie,
        total_queries: u64,
        queries: Q,
    ) -> Result<
        impl Stream<Item = Result<StreamChunk<CompressedHashPart>, HttpError>> + Send,
        HttpError,
    >
    where
        Q: TryStream + Send + 'static,
        Q::Ok: Deref<Target = [CompressedQuery]>,
        Q::Error: std::error::Error + Send + Sync,
    {
        let api_client = add_session(&self.api_client, session_id);
        let uri = format!("{}{}", self.domain, scep::KEYSERVE_ENDPOINT);
        let stream = Streamed {
            chunks: queries,
            total_elements: Some(total_queries),
        };
        let response: Streamed<_> = api_client.post(uri, stream).await?;
        // Ack, apparently our keyservers aren't setting content-length?
        // Looks like I'll have to hold off adding this.
        // if response.total_elements != Some(total_queries) {
        //     return Err(HttpError::ProtocolError {
        //         error: "keyserver might not send back correct number of hashparts".to_owned(),
        //     });
        // }
        Ok(response.chunks.map_err(|err| HttpError::DecodeError {
            decoding: "compressed hash parts".to_owned(),
            source: err.into(),
        }))
    }
}

#[derive(Clone)]
pub struct HdbOpenParams {
    pub region: Region,
    pub with_exemption: bool,
    pub verifiable: VerifiableScreeningRequested,
    /// Hex digest of SHA3-256 hash of the JSON posted to synthclient. Used for verifiable screening.
    ///
    /// This field is a bit of a misnomer: the hash is not just over a FASTA,
    /// but over a larger JSON object also containing region and exemption data.
    pub fasta_sha3_256_hex: String,
    /// The version string reported by synthclient. Used for verifiable
    /// screening. This is the same string as returned by `GET /version`,
    /// containing a version number and a commit hash, like "1.2.3-a4b5c6d" or
    /// "1.2.3-dev-a4b5c6d".
    pub synthclient_version: String,
}

impl ScepClient<DatabaseTokenGroup> {
    pub async fn open(
        &self,
        common_params: ScepClientOpenCommon,
        hdb_params: HdbOpenParams,
    ) -> Result<OpenedClientState, Error<scep::error::ClientPrevalidation>> {
        let hash = hdb_params.fasta_sha3_256_hex;
        if hdb_params.verifiable == VerifiableScreeningRequested::Requested {
            let hash_valid = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
            if !hash_valid {
                return Err(Error::Scep {
                    source: scep::error::ClientPrevalidation::InvalidFastaHash.into(),
                    domain: self.domain.clone(),
                });
            }
        }
        let common = ScreenCommon {
            region: hdb_params.region,
            provider_reference: None,
            verifiable: hdb_params.verifiable,
            fasta_sha3_256_hex: hash.to_ascii_lowercase(),
            synthclient_version: hdb_params.synthclient_version,
        };
        let request_type = if hdb_params.with_exemption {
            ClientRequestType::ScreenWithExemption(common)
        } else {
            ClientRequestType::Screen(common)
        };
        self.generic_open(
            request_type,
            common_params,
            scep::steps::client_prevalidate_and_mutual_auth_hdb,
        )
        .await
    }

    pub async fn screen(
        &self,
        session_id: SessionCookie,
        hashes: &PackedRistrettos<TaggedHash>,
    ) -> Result<HdbScreeningResult, HttpError> {
        self.screen_with_ets(session_id, hashes, &[], &Default::default())
            .await
    }

    pub async fn screen_with_ets(
        &self,
        session_id: SessionCookie,
        hashes: &PackedRistrettos<TaggedHash>,
        ets: &[WithOtps<TokenBundle<ExemptionTokenGroup>>],
        et_hashes: &PackedRistrettos<CompressedCompletedHashValue>,
    ) -> Result<HdbScreeningResult, HttpError> {
        let (total_hashes, hashes) = packed_to_len_and_stream(hashes, "hashes")?;
        let (total_et_hashes, et_hashes) =
            packed_to_len_and_stream(et_hashes, "exemption token hashes")?;
        self.screen_streamed(
            session_id,
            hashes,
            total_hashes,
            ets,
            et_hashes,
            total_et_hashes,
        )
        .await
    }

    pub async fn screen_streamed<H, EH>(
        &self,
        session_id: SessionCookie,
        hashes: H,
        total_hashes: u64,
        ets: &[WithOtps<TokenBundle<ExemptionTokenGroup>>],
        et_hashes: EH,
        total_et_hashes: u64,
    ) -> Result<HdbScreeningResult, HttpError>
    where
        H: TryStream + Send + 'static,
        H::Ok: Deref<Target = [TaggedHash]>,
        H::Error: Into<BoxedError> + Send + Sync,
        EH: TryStream + Send + 'static,
        EH::Ok: Deref<Target = [CompressedCompletedHashValue]>,
        EH::Error: Into<BoxedError> + Send + Sync,
    {
        let api_client = add_session(&self.api_client, session_id);
        let hashes = Streamed {
            chunks: hashes,
            total_elements: Some(total_hashes),
        };
        if ets.is_empty() {
            let uri = format!("{}{}", self.domain, scep::SCREEN_ENDPOINT);
            let Json(hdb_result) = api_client.post(uri, hashes).await?;
            Ok(hdb_result)
        } else {
            let et_pems: Result<Vec<_>, _> = ets
                .iter()
                .map(|w| w.as_ref().try_map(|e| e.to_file_contents()))
                .collect();
            let et_pems = et_pems.map_err(|e| HttpError::EncodeError {
                encoding: "exemption token".to_owned(),
                source: e.into(),
            })?;

            let et_wire = serde_json::to_vec(&et_pems).map_err(|e| HttpError::EncodeError {
                encoding: "exemption token".to_owned(),
                source: e.into(),
            })?;
            let et_size = et_wire.len().try_into().unwrap_or(u64::MAX);

            let uri = format!("{}{}", self.domain, scep::SCREEN_WITH_EXEMPTION_ENDPOINT);
            let _: Json<serde_json::Value> = api_client
                .post(uri, Json(ScreenWithExemptionParams { et_size }))
                .await?;
            let uri = format!("{}{}", self.domain, scep::EXEMPTION_ENDPOINT);
            let body = Bytes::from(et_wire).with_content_type(Json::CONTENT_TYPE);
            let Json(response): Json<EtEndpointResponse> = api_client.post(uri, body).await?;

            let has_dna = ets.iter().any(|w| w.et.token.has_dna_sequences());
            if response.needs_hashes && !has_dna {
                return Err(HttpError::ProtocolError {
                    error: "Server says we need to send hashes, \
                            but our exemption tokens have no DNA sequences."
                        .to_owned(),
                });
            }
            if !response.needs_hashes && has_dna {
                return Err(HttpError::ProtocolError {
                    error: "Server says we don't need to send hashes, \
                            but our exemption tokens have DNA sequences."
                        .to_owned(),
                });
            }

            if response.needs_hashes {
                let et_hashes = Streamed {
                    chunks: et_hashes,
                    total_elements: Some(total_et_hashes),
                };
                let uri = format!("{}{}", self.domain, scep::EXEMPTION_SEQ_HASHES_ENDPOINT);
                let _: Json<serde_json::Value> = api_client.post(uri, et_hashes).await?;
            }
            let uri = format!("{}{}", self.domain, scep::EXEMPTION_SCREEN_HASHES_ENDPOINT);
            let Json(hdb_result) = api_client.post(uri, hashes).await?;
            Ok(hdb_result)
        }
    }
}

fn add_session(api_client: &BaseApiClient, session_id: SessionCookie) -> BaseApiClient {
    let (header, value) = session_id.to_http_header();
    add_header(api_client.service().clone(), header, value).into()
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

fn packed_to_len_and_stream<T: PackableRistretto>(
    packed: &PackedRistrettos<T>,
    description: &'static str,
) -> HttpResult<(u64, impl Stream<Item = RistrettoChunk<T>>)> {
    let total_elements = u64::try_from(packed.len()).map_err(|err| HttpError::EncodeError {
        encoding: description.to_owned(),
        source: err.into(),
    })?;
    let stream = futures::stream::iter([packed.iter_decoded().collect()]);
    Ok((total_elements, stream))
}

type HttpResult<T> = Result<T, HttpError>;
type RistrettoChunk<T> = Result<Vec<T>, PackedRistrettoError<T>>;
type PackedRistrettoError<T> = <T as TryFrom<<T as PackableRistretto>::Array>>::Error;
