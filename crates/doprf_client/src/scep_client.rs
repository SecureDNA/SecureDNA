// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use futures::stream::FuturesUnordered;
use futures::TryStreamExt;

use crate::error::DoprfError;
use crate::retry_if;
use crate::server_selection::{bad_flag::ServerBadFlag, SelectedHdb, SelectedKeyserver};
use certificates::{DatabaseTokenGroup, ExemptionListTokenGroup, KeyserverTokenGroup, TokenBundle};
use doprf::party::{KeyserverId, KeyserverIdSet};
use doprf::prf::{CompletedHashValue, HashPart, Query};
use doprf::tagged::TaggedHash;
use http_client::BaseApiClient;
use packed_ristretto::PackedRistrettos;
use scep::states::OpenedClientState;
use scep_client_helpers::{ClientCerts, ScepClient};
use shared_types::hdb::HdbScreeningResult;
use shared_types::synthesis_permission::Region;

#[derive(Clone)]
pub struct ClientConfig {
    pub api_client: BaseApiClient,
    pub certs: Arc<ClientCerts>,
    pub version_hint: String,
}

pub struct HdbClient {
    client: ScepClient<DatabaseTokenGroup>,
    server: SelectedHdb,
    pub state: OpenedClientState,
}

impl HdbClient {
    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        server: SelectedHdb,
        config: ClientConfig,
        nucleotide_total_count: u64,
        last_server_version: Option<u64>,
        keyserver_id_set: KeyserverIdSet,
        region: Region,
        with_exemption_list: bool,
    ) -> Result<Self, DoprfError> {
        let client = ScepClient::<DatabaseTokenGroup>::new(
            config.api_client,
            format!("https://{}", server.domain),
            config.certs,
            config.version_hint,
        );

        let state = retry_with_timeout_and_mark_bad(
            || async {
                Ok(client
                    .open(
                        nucleotide_total_count,
                        last_server_version,
                        keyserver_id_set.clone(),
                        region,
                        with_exemption_list,
                    )
                    .await?)
            },
            &server.bad_flag,
        )
        .await?;

        Ok(Self {
            client,
            server,
            state,
        })
    }

    /// Post packed `TaggedHash`es to the HDB, and return the HDB response set
    pub async fn query(
        self,
        hashes: &PackedRistrettos<TaggedHash>,
    ) -> Result<HdbScreeningResult, DoprfError> {
        let hash_total_count = hashes
            .len()
            .try_into()
            .map_err(|_| DoprfError::SequencesTooBig)?;

        retry_with_timeout_and_mark_bad(
            || async {
                Ok(self
                    .client
                    .authenticate(self.state.clone(), hash_total_count)
                    .await?)
            },
            &self.server.bad_flag,
        )
        .await?;

        retry_with_timeout_and_mark_bad(
            || async { Ok(self.client.screen(hashes).await?) },
            &self.server.bad_flag,
        )
        .await
    }

    /// Post packed `CompletedHashValue`s to the HDB, and return the HDB response set
    pub async fn query_with_elt(
        self,
        hashes: &PackedRistrettos<TaggedHash>,
        elt: &TokenBundle<ExemptionListTokenGroup>,
        elt_hashes: PackedRistrettos<CompletedHashValue>,
        otp: String,
    ) -> Result<HdbScreeningResult, DoprfError> {
        let hash_total_count = hashes
            .len()
            .try_into()
            .map_err(|_| DoprfError::SequencesTooBig)?;

        retry_with_timeout_and_mark_bad(
            || async {
                Ok(self
                    .client
                    .authenticate(self.state.clone(), hash_total_count)
                    .await?)
            },
            &self.server.bad_flag,
        )
        .await?;

        retry_with_timeout_and_mark_bad(
            || async {
                Ok(self
                    .client
                    .screen_with_elt(hashes, elt, &elt_hashes, otp.clone())
                    .await?)
            },
            &self.server.bad_flag,
        )
        .await
    }

    pub fn domain(&self) -> &str {
        &self.server.domain
    }

    pub fn server_version(&self) -> u64 {
        self.state.server_version
    }
}

pub struct KeyserverClient {
    client: ScepClient<KeyserverTokenGroup>,
    server: SelectedKeyserver,
    state: OpenedClientState,
}

impl KeyserverClient {
    pub async fn open(
        server: SelectedKeyserver,
        config: ClientConfig,
        nucleotide_total_count: u64,
        last_server_version: Option<u64>,
        keyserver_id_set: KeyserverIdSet,
    ) -> Result<Self, DoprfError> {
        let client = ScepClient::<KeyserverTokenGroup>::new(
            config.api_client,
            format!("https://{}", server.domain),
            config.certs,
            config.version_hint,
        );

        let state = retry_with_timeout_and_mark_bad(
            || async {
                Ok(client
                    .open(
                        nucleotide_total_count,
                        last_server_version,
                        keyserver_id_set.clone(),
                        server.id,
                    )
                    .await?)
            },
            &server.bad_flag,
        )
        .await?;

        Ok(Self {
            client,
            server,
            state,
        })
    }

    /// Post packed `Query`s to the given keyserver, and return the response of packed `HashPart`s
    pub async fn query(
        self,
        hash_total_count: u64,
        queries: &PackedRistrettos<Query>,
    ) -> Result<PackedRistrettos<HashPart>, DoprfError> {
        retry_with_timeout_and_mark_bad(
            || async {
                Ok(self
                    .client
                    .authenticate(self.state.clone(), hash_total_count)
                    .await?)
            },
            &self.server.bad_flag,
        )
        .await?;

        retry_with_timeout_and_mark_bad(
            || async { Ok(self.client.keyserve(queries).await?) },
            &self.server.bad_flag,
        )
        .await
    }

    pub fn domain(&self) -> &str {
        &self.server.domain
    }

    pub fn server_version(&self) -> u64 {
        self.state.server_version
    }
}

pub struct KeyserverSetClient {
    clients: Vec<KeyserverClient>,
}

impl KeyserverSetClient {
    /// Open an SCEP session with all keyservers in parallel
    pub async fn open(
        servers: impl IntoIterator<Item = (SelectedKeyserver, Option<u64>)>,
        config: ClientConfig,
        nucleotide_total_count: u64,
        keyserver_id_set: KeyserverIdSet,
    ) -> Result<Self, DoprfError> {
        let clients = servers
            .into_iter()
            .map(|(s, last_server_version)| {
                KeyserverClient::open(
                    s,
                    config.clone(),
                    nucleotide_total_count,
                    last_server_version,
                    keyserver_id_set.clone(),
                )
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await?;
        Ok(Self { clients })
    }

    /// Query all keyservers in parallel, returning an error on first failure
    pub async fn query(
        self,
        hash_total_count: u64,
        queries: &PackedRistrettos<Query>,
    ) -> Result<Vec<(KeyserverId, PackedRistrettos<HashPart>)>, DoprfError> {
        self.clients
            .into_iter()
            .map(|client| {
                let client_id = client.server.id;
                async move {
                    client
                        .query(hash_total_count, queries)
                        .await
                        .map(|hash_parts| (client_id, hash_parts))
                }
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await
    }

    pub fn clients(&self) -> impl Iterator<Item = &KeyserverClient> {
        self.clients.iter()
    }
}

/// Helper for hdb and keyserver api clients: retry the given future with our
/// retry and timeout schedule, and mark the server error flag if we don't get a
/// response within the given number of retries.
async fn retry_with_timeout_and_mark_bad<Fut, Val>(
    mut mk_future: impl FnMut() -> Fut,
    server_bad_flag: &ServerBadFlag,
) -> Result<Val, DoprfError>
where
    Fut: futures::Future<Output = Result<Val, DoprfError>>,
{
    const TIMEOUT: Duration = Duration::from_secs(120);
    // this is 4 tries overall, 1 try + 3 retries. confusing...
    let policy = retry_if::retry_policy_jittered_fibonacci().with_max_retries(3);

    let mut mk_future = || retry_if::with_timeout(TIMEOUT, mk_future());

    // we want to return the first error we get, since with SCEP sessions that's most likely
    // the root cause (since SCEP drops the session on error, retrying an SCEP-originated
    // error leads to a 400 unknown cookie error, which isn't helpful.)
    //
    // However, if the first try succeeded, or the first try resulted in a non-retriable error,
    // we should immediately return.
    let first_err = match mk_future().await {
        Err(e) if e.is_retriable() => e,
        result => return result,
    };

    let mut skip_try = true;
    let mk_future = || {
        if skip_try {
            // account for the first try we already did
            skip_try = false;
            futures::future::Either::Left(async { Err(true) })
        } else {
            let future = mk_future();
            futures::future::Either::Right(async { future.await.map_err(|e| e.is_retriable()) })
        }
    };

    policy
        .retry_if(mk_future, |is_retriable: &bool| *is_retriable)
        .await
        .map_err(|_| {
            server_bad_flag.mark_bad();
            first_err
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http_client::HttpError;

    use crate::{
        error::DoprfError, scep_client::retry_with_timeout_and_mark_bad,
        server_selection::bad_flag::ServerBadFlag,
    };

    #[tokio::test]
    async fn test_retry_err() {
        let state = Arc::new(tokio::sync::Mutex::new(0u8));

        let mk_future = || async {
            let mut guard = state.lock().await;
            *guard += 1;
            // pack current `state` into error domain
            Result::<(), _>::Err(DoprfError::HttpError(
                http_client::HttpError::RequestError {
                    ctx: format!("error #{guard}"),
                    status: Some(418),
                    retriable: true,
                    source: "i'm a teapot".into(),
                },
            ))
        };

        let server_bad_flag = ServerBadFlag::default();

        let ctx = match retry_with_timeout_and_mark_bad(mk_future, &server_bad_flag)
            .await
            .unwrap_err()
        {
            DoprfError::HttpError(HttpError::RequestError {
                ctx,
                retriable: true,
                ..
            }) => ctx,
            v => panic!("expected retriable HTTP request error, got {v:?}"),
        };

        // should have tried four times
        assert_eq!(*state.lock().await, 4);
        // should have kept first error
        assert_eq!(ctx, "error #1");
    }

    #[tokio::test]
    async fn test_retry_non_retriable_err() {
        let state = Arc::new(tokio::sync::Mutex::new(0u8));

        let mk_future = || async {
            let mut guard = state.lock().await;
            *guard += 1;
            // pack current `state` into error domain
            Result::<(), _>::Err(DoprfError::HttpError(
                http_client::HttpError::RequestError {
                    ctx: format!("error #{guard}"),
                    status: Some(418),
                    retriable: false,
                    source: "i'm a teapot".into(),
                },
            ))
        };

        let server_bad_flag = ServerBadFlag::default();

        let ctx = match retry_with_timeout_and_mark_bad(mk_future, &server_bad_flag)
            .await
            .unwrap_err()
        {
            DoprfError::HttpError(HttpError::RequestError {
                ctx,
                retriable: false,
                ..
            }) => ctx,
            v => panic!("expected non-retriable HTTP request error, got {v:?}"),
        };

        // should have only tried once
        assert_eq!(*state.lock().await, 1);
        // should have kept first error
        assert_eq!(ctx, "error #1");
    }

    #[tokio::test]
    async fn test_retry_success() {
        let state = Arc::new(tokio::sync::Mutex::new(0u8));

        let mk_future = || async {
            let mut guard = state.lock().await;
            *guard += 1;
            Ok(*guard)
        };

        let server_bad_flag = ServerBadFlag::default();

        let v = retry_with_timeout_and_mark_bad(mk_future, &server_bad_flag)
            .await
            .unwrap();

        // should have only tried once
        assert_eq!(v, 1);
    }

    #[tokio::test]
    async fn test_retry_fail_then_success() {
        let state = Arc::new(tokio::sync::Mutex::new(0u8));

        let mk_future = || async {
            let mut guard = state.lock().await;
            *guard += 1;
            if *guard == 1 {
                Err(DoprfError::HttpError(HttpError::RequestError {
                    ctx: "".into(),
                    status: Some(418),
                    retriable: true,
                    source: "i'm a teapot".into(),
                }))
            } else {
                Ok(*guard)
            }
        };

        let server_bad_flag = ServerBadFlag::default();

        let v = retry_with_timeout_and_mark_bad(mk_future, &server_bad_flag)
            .await
            .unwrap();

        // should have tried twice
        assert_eq!(v, 2);
    }
}
