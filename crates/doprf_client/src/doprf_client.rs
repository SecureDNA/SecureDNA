// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fmt::{self, Display};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::FuturesUnordered;
use futures::TryStreamExt;

use crate::error::DOPRFError;
use crate::instant::get_now;
use crate::operations::{incorporate_responses_and_hash, make_keyserver_querysets};
use crate::retry_if;
use crate::server_selection::{
    bad_flag::ServerBadFlag, ChosenSelectionSubset, SelectedHdb, SelectedKeyserver, ServerSelector,
};
use crate::windows::Windows;
use certificates::{DatabaseTokenGroup, KeyserverTokenGroup};
use doprf::party::{KeyserverId, KeyserverIdSet};
use doprf::prf::{HashPart, Query};
use doprf::tagged::TaggedHash;
use http_client::BaseApiClient;
use packed_ristretto::PackedRistrettos;
use quickdna::ToNucleotideLike;
use scep::states::OpenedClientState;
use scep_client_helpers::{ClientCerts, ScepClient};
use shared_types::hdb::HdbScreeningResult;
use shared_types::info_with_timestamp;
use shared_types::synthesis_permission::Region;
use shared_types::{debug_with_timestamp, requests::RequestContext};

pub struct HdbClient<'a> {
    client: ScepClient<DatabaseTokenGroup>,
    server: &'a SelectedHdb,
    state: OpenedClientState,
}

impl<'a> HdbClient<'a> {
    pub async fn open(
        api_client: BaseApiClient,
        server: &'a SelectedHdb,
        certs: Arc<ClientCerts>,
        version_hint: String,
        nucleotide_total_count: u64,
        keyserver_id_set: KeyserverIdSet,
        region: Region,
    ) -> Result<Self, DOPRFError> {
        let client = ScepClient::<DatabaseTokenGroup>::new(
            api_client,
            format!("https://{}", server.domain),
            certs,
            version_hint,
        );

        let state = retry_with_timeout_and_mark_bad(
            || async {
                Ok(client
                    .open(
                        nucleotide_total_count,
                        None, // TODO: last_server_version
                        keyserver_id_set.clone(),
                        region,
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

    /// Post packed `CompletedHashValue`s to the HDB, and return the HDB response set
    pub async fn query(
        self,
        hash_total_count: u64,
        hashes: &PackedRistrettos<TaggedHash>,
    ) -> Result<HdbScreeningResult, DOPRFError> {
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
}

pub struct KeyserverClient {
    client: ScepClient<KeyserverTokenGroup>,
    server: SelectedKeyserver,
    state: OpenedClientState,
}

impl KeyserverClient {
    pub async fn open(
        api_client: BaseApiClient,
        server: SelectedKeyserver,
        certs: Arc<ClientCerts>,
        version_hint: String,
        nucleotide_total_count: u64,
        keyserver_id_set: KeyserverIdSet,
    ) -> Result<Self, DOPRFError> {
        let client = ScepClient::<KeyserverTokenGroup>::new(
            api_client,
            format!("https://{}", server.domain),
            certs,
            version_hint,
        );

        let state = retry_with_timeout_and_mark_bad(
            || async {
                Ok(client
                    .open(
                        nucleotide_total_count,
                        None, // TODO: last_server_version
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
    ) -> Result<PackedRistrettos<HashPart>, DOPRFError> {
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
}

/// Helper for hdb and keyserver api clients: retry the given future with our
/// retry and timeout schedule, and mark the server error flag if we don't get a
/// response within the given number of retries.
async fn retry_with_timeout_and_mark_bad<Fut, Val>(
    mut mk_future: impl FnMut() -> Fut,
    server_bad_flag: &ServerBadFlag,
) -> Result<Val, DOPRFError>
where
    Fut: futures::Future<Output = Result<Val, DOPRFError>>,
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

#[derive(Debug)]
pub struct UnexpectedResponseCount {
    expected: usize,
    actual: usize,
}

impl Error for UnexpectedResponseCount {}

impl Display for UnexpectedResponseCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unexpected element count in response, expected {0} but received {1}",
            self.expected, self.actual
        )
    }
}

pub struct KeyserverSetClient {
    clients: Vec<KeyserverClient>,
}

impl KeyserverSetClient {
    /// Open an SCEP session with all keyservers in parallel
    pub async fn open(
        servers: &[SelectedKeyserver],
        api_client: &BaseApiClient,
        certs: Arc<ClientCerts>,
        version_hint: String,
        nucleotide_total_count: u64,
        keyserver_id_set: KeyserverIdSet,
    ) -> Result<Self, DOPRFError> {
        let clients = servers
            .iter()
            .map(|s| {
                KeyserverClient::open(
                    api_client.clone(),
                    s.clone(),
                    certs.clone(),
                    version_hint.clone(),
                    nucleotide_total_count,
                    keyserver_id_set.clone(),
                )
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await?;
        Ok(Self { clients })
    }

    /// Query all keyservers in parallel, returning an error on first failure
    async fn query(
        self,
        hash_total_count: u64,
        queries: &PackedRistrettos<Query>,
    ) -> Result<Vec<(KeyserverId, PackedRistrettos<HashPart>)>, DOPRFError> {
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
}

pub struct DOPRFConfig<'a, S> {
    pub api_client: &'a BaseApiClient,
    pub server_selector: Arc<ServerSelector>,
    pub request_ctx: &'a RequestContext,
    pub certs: Arc<ClientCerts>,
    pub region: Region,
    pub debug: bool,
    pub sequences: &'a [S],
    pub max_windows: u64,
    /// A freeform version hint for the caller, used for tracking client
    /// distribution (similar to User-Agent in HTTP)
    pub version_hint: String,
}

#[derive(Debug)]
pub struct DOPRFOutput {
    /// The number of hashes sent to the HDB
    pub n_hashes: u64,
    /// True iff all sequences are shorter than the minimum length demanded by the hash spec.
    pub too_short: bool,
    /// The consolidation returned from the HDB
    pub response: HdbScreeningResult,
}

/// Takes a slice of sequences, hashes them, sends them to the keyservers,
/// then sends the results to the hdb, per the DOPRF protocol.
///
/// Attaches the given request_id to each request sent.
///
/// Returns a `DOPRFSequenceResult` for each matching sequence, which includes the
/// index of that sequence in the given `sequences` slice.
pub async fn process<'a, N: ToNucleotideLike + Copy + 'a, S: AsRef<[N]>>(
    config: DOPRFConfig<'a, S>,
) -> Result<DOPRFOutput, DOPRFError> {
    // if either of these return an error, then a refresh is required by whoever holds the server selector
    // not our problem! they need to check DOPRFError::SelectionRefreshRequired
    let ChosenSelectionSubset {
        keyserver_threshold,
        active_security_key,
        keyservers,
        hdb,
    } = config.server_selector.choose().await?;

    let nucleotide_total_count = config
        .sequences
        .iter()
        .map(|seq| seq.as_ref().len())
        .try_fold(0u64, |total, len| total.checked_add(len.try_into().ok()?))
        .ok_or(DOPRFError::SequencesTooBig)?;

    if nucleotide_total_count == 0 {
        info_with_timestamp!("{}: all sequences were empty", config.request_ctx.id);
        return Ok(DOPRFOutput {
            n_hashes: 0,
            too_short: true,
            response: HdbScreeningResult::default(),
        });
    }

    let keyserver_id_set: KeyserverIdSet =
        keyservers.iter().map(|ks| ks.id).collect::<Vec<_>>().into();

    info_with_timestamp!(
        "{}: selected keyservers=[{}], hdb={}",
        config.request_ctx.id,
        keyservers
            .iter()
            .fold(String::new(), |mut s, ks| {
                s.push_str(", ");
                s.push_str(&ks.to_string());
                s
            })
            .trim_start_matches([' ', ',']),
        hdb
    );

    let keyserver_set_client = KeyserverSetClient::open(
        &keyservers,
        config.api_client,
        config.certs.clone(),
        config.version_hint.clone(),
        nucleotide_total_count,
        keyserver_id_set.clone(),
    )
    .await?;
    let hdb_client = HdbClient::open(
        config.api_client.clone(),
        &hdb,
        config.certs.clone(),
        config.version_hint.clone(),
        nucleotide_total_count,
        keyserver_id_set.clone(),
        config.region,
    )
    .await?;

    if let Some(min) = hdb_client.state.hash_spec.min_width_bp() {
        if config.sequences.iter().all(|seq| seq.as_ref().len() < min) {
            return Ok(DOPRFOutput {
                n_hashes: 0,
                too_short: true,
                response: HdbScreeningResult::default(),
            });
        }
    }

    let window_iters = config
        .sequences
        .iter()
        .map(|seq| Windows::from_dna(seq.as_ref().iter().copied(), &hdb_client.state.hash_spec))
        .collect::<Result<Vec<_>, _>>()?;

    let n_windows = window_iters
        .iter()
        .map(|iter| iter.size_hint().1)
        .try_fold(0u64, |total, len| total.checked_add(len?.try_into().ok()?))
        .ok_or(DOPRFError::SequencesTooBig)?;

    if n_windows > config.max_windows {
        return Err(DOPRFError::SequencesTooBig);
    }

    // add one for active security
    let hash_total_count = n_windows
        .checked_add(1)
        .ok_or(DOPRFError::SequencesTooBig)?;

    // Allows us to assume the next `as u64` will always work.
    if u64::try_from(window_iters.len()).is_err() {
        return Err(DOPRFError::SequencesTooBig);
    }
    let non_empty_records: Vec<_> = window_iters
        .iter()
        .enumerate()
        .filter_map(|(record, iter)| (iter.size_hint().0 > 0).then_some(record as u64))
        .collect();

    let combined_windows: Vec<_> = window_iters.into_iter().flatten().collect();

    if n_windows == 0 {
        info_with_timestamp!("{}: didn't generate any windows", config.request_ctx.id);
        return Ok(DOPRFOutput {
            n_hashes: 0,
            too_short: false,
            response: HdbScreeningResult::default(),
        });
    }
    info_with_timestamp!("{}: generated {} windows", config.request_ctx.id, n_windows);

    let querystate = make_keyserver_querysets(
        config.request_ctx,
        &combined_windows,
        keyserver_threshold as usize,
        &active_security_key,
    )?;

    // query keyservers with initial hash to get keyserver response querysets of hashes
    let now = get_now();
    let querystate_ristrettos = PackedRistrettos::<Query>::from(&querystate);
    let keyserver_responses = keyserver_set_client
        .query(hash_total_count, &querystate_ristrettos)
        .await?;
    let querying_duration = now.elapsed();
    debug_with_timestamp!("Querying key servers done. Took: {:.2?}", querying_duration);

    let hashes =
        incorporate_responses_and_hash(config.request_ctx, querystate, keyserver_responses).await?;

    // query HDB with final hashes
    let now = get_now();
    let mut response = hdb_client.query(hash_total_count, &hashes).await?;
    let hdb_duration = now.elapsed();
    debug_with_timestamp!("Querying HDB done. Took: {:.2?}", hdb_duration);

    // The HDB sets `record` based on how many new-record flags it has encountered, but
    // sufficiently small FASTA records won't produce windows, so the `record`s returned
    // by the HDB need to be fixed up to account for records without windows.
    for hazard in &mut response.results {
        hazard.record = *usize::try_from(hazard.record)
            .ok()
            .and_then(|hdb_record| non_empty_records.get(hdb_record))
            .ok_or(DOPRFError::InvalidRecord)?;
    }

    Ok(DOPRFOutput {
        n_hashes: n_windows,
        too_short: false,
        response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::FutureExt;
    use http_client::HTTPError;
    use quickdna::{BaseSequence, DnaSequence, FastaContent, Nucleotide};

    use crate::server_selection::test_utils::{
        make_test_selection, make_test_selector, peek_selector_selection,
    };
    use crate::server_selection::{
        ServerEnumerationSource, ServerSelectionConfig, ServerSelectionError,
    };
    use http_client::test_utils::ApiClientCoreMock;
    use shared_types::requests::RequestId;

    #[tokio::test]
    async fn test_bad_mark_applied() {
        // set up every request to fail (retriably)
        let mock_api_client = BaseApiClient::from(ApiClientCoreMock::from(
            |url: String, _body, _content_type, _headers, _expected_content_type| {
                async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Err(http_client::error::HTTPError::RequestError {
                        ctx: url,
                        retriable: true,
                        source: "i'm a teapot".into(),
                    })
                }
                .boxed()
            },
        ));

        // define 3 keyservers (all with unique ids--no replicas) with a 2-server threshold
        let selection = make_test_selection(
            2,
            &[
                ("seattle.keyserver", 1),
                ("sf.keyserver", 2),
                ("portland.keyserver", 3),
            ],
            &["hdb"],
        );
        let selector = Arc::new(make_test_selector(
            ServerSelectionConfig {
                enumeration_source: ServerEnumerationSource::Fixed {
                    keyserver_domains: vec![],
                    hdb_domains: vec![],
                },
                soft_timeout: None,
                blocking_timeout: None,
                soft_extra_keyserver_threshold: None,
                soft_extra_hdb_threshold: None,
            },
            mock_api_client.clone(),
            selection,
            get_now(),
        ));

        let request_ctx = RequestContext::single(RequestId::new_unique());
        let certs = Arc::new(ClientCerts::load_test_certs());

        let dna = DnaSequence::<Nucleotide>::parse(0, "atcgatcgatcgatcgatcg").unwrap();

        // take a first spin
        process(DOPRFConfig {
            api_client: &mock_api_client,
            server_selector: selector.clone(),
            request_ctx: &request_ctx,
            certs: certs.clone(),
            region: Region::All,
            debug: false,
            sequences: &[dna.as_slice()],
            max_windows: u64::MAX,
            version_hint: "test".to_owned(),
        })
        .await
        .unwrap_err();

        let selection = peek_selector_selection(&selector).await;
        // only one keyserver (whichever failed first) should now have a bad mark
        assert_eq!(selection.available_keyservers(), 2);
        // the hdb should not be marked bad, since it wasn't reached
        assert_eq!(selection.available_hdbs(), 1);

        // take another whack
        process(DOPRFConfig {
            api_client: &mock_api_client,
            server_selector: selector.clone(),
            request_ctx: &request_ctx,
            certs: certs.clone(),
            region: Region::All,
            debug: false,
            sequences: &[dna.as_slice()],
            max_windows: u64::MAX,
            version_hint: "test".to_owned(),
        })
        .await
        .unwrap_err();

        let selection = peek_selector_selection(&selector).await;
        // now *two* keyservers should have bad marks
        assert_eq!(selection.available_keyservers(), 1);
        // the hdb should still not be marked bad
        assert_eq!(selection.available_hdbs(), 1);

        // trying to choose should fail, since two keyservers are bad, and the fixed DNS is empty
        assert!(matches!(
            selector.choose().await.unwrap_err(),
            ServerSelectionError::NoQuorum(_),
        ));
    }

    #[tokio::test]
    async fn test_retry_err() {
        let state = Arc::new(tokio::sync::Mutex::new(0u8));

        let mk_future = || async {
            let mut guard = state.lock().await;
            *guard += 1;
            // pack current `state` into error domain
            Result::<(), _>::Err(DOPRFError::HttpError(
                http_client::HTTPError::RequestError {
                    ctx: format!("error #{guard}"),
                    retriable: true,
                    source: "".into(),
                },
            ))
        };

        let server_bad_flag = ServerBadFlag::default();

        let ctx = match retry_with_timeout_and_mark_bad(mk_future, &server_bad_flag)
            .await
            .unwrap_err()
        {
            DOPRFError::HttpError(HTTPError::RequestError {
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
            Result::<(), _>::Err(DOPRFError::HttpError(
                http_client::HTTPError::RequestError {
                    ctx: format!("error #{guard}"),
                    retriable: false,
                    source: "".into(),
                },
            ))
        };

        let server_bad_flag = ServerBadFlag::default();

        let ctx = match retry_with_timeout_and_mark_bad(mk_future, &server_bad_flag)
            .await
            .unwrap_err()
        {
            DOPRFError::HttpError(HTTPError::RequestError {
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
                Err(DOPRFError::HttpError(HTTPError::RequestError {
                    ctx: "".into(),
                    retriable: true,
                    source: "".into(),
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
