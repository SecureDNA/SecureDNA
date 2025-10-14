// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use futures::{TryStream, TryStreamExt};
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::error::DoprfError;
use crate::instant::get_now;
use crate::scep_client::{ClientConfig, HdbClient, KeyserverSetClient};
use crate::server_selection::{ChosenSelectionSubset, SelectedKeyserver, ServerSelector};
use crate::server_version_handler::LastServerVersionHandler;
use crate::stream::{HashingConfig, HashingStreamError};
use crate::windows::{OrderWindow, OrderWindows};
use certificates::{ExemptionTokenGroup, TokenBundle};
use doprf::active_security::ActiveSecurityKey;
use doprf::party::KeyserverIdSet;
use doprf::prf::CompressedCompletedHashValue;
use doprf::tagged::{HashTag, TaggedHash};
use hdb_api::HdbScreeningResult;
use http_client::BaseApiClient;
use quickdna::ToNucleotideLike;
use scep::types::VerifiableScreeningRequested;
use scep_client_helpers::scep_client::HdbOpenParams;
use scep_client_helpers::{ClientCerts, ScepClientOpenCommon};
use shared_types::et::WithOtps;
use shared_types::hash::HashSpec;
use shared_types::requests::RequestContext;
use shared_types::requests::RequestId;
use shared_types::synthesis_permission::Region;

#[derive(Clone)]
pub struct ScreeningParams {
    pub certs: Arc<ClientCerts>,
    pub include_debug_info: bool,
    /// Whether the client requests verifiable screening
    pub verifiable_screening: bool,
    pub region: Region,
    /// Exemption tokens.
    pub ets: Vec<WithOtps<TokenBundle<ExemptionTokenGroup>>>,
    /// Hex digest of SHA3-256 hash of the JSON posted to synthclient. Used for
    /// verifiable screening.
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

pub struct DoprfConfig<'a, S> {
    pub api_client: &'a BaseApiClient,
    pub server_selector: Arc<ServerSelector>,
    pub request_ctx: &'a RequestContext,
    pub sequences: &'a [S],
    pub max_windows: u64,
    /// A freeform version hint for the caller, used for tracking client
    /// distribution (similar to User-Agent in HTTP)
    pub version_hint: String,
    pub server_version_handler: &'a LastServerVersionHandler,
    pub params: ScreeningParams,
    /// Tunes how many parallel tasks this DOPRF run attempts.
    ///
    /// Multi-threading is handled the stupid/obvious way: [`Stream`]s of work get mapped to
    /// [`Future`]s that execute the work in [`tokio`] background threads, and
    /// [`StreamExt::buffered`] is used to run multiple units of work simultaneously.
    /// In order to avoid overwhelming the system with [`tokio`] background threads, each
    /// [`Future`] holds a [`Semaphore`] while the background thread is running. Thus we
    /// need two settings:
    /// * [`parallelism_per_request`](Self::parallelism_per_request`), which controls
    ///   [`StreamExt::buffered`] for each step that needs to be parallelized (currently
    ///   there are two: pre-KS crypto and post-KS crypto).
    /// * [`server_parallelism_limit`](Self::server_parallelism_limit), which is the
    ///   [`Semaphore`] acting as a server-wide limit for the number of background threads.
    ///
    /// Note that [`tokio`] doesn't support spawning background threads on WASM, so this
    /// doesn't affect parallelism of crypto tasks there. However, it currently *does* affect
    /// [`HashingConfig::keyserver_disparity_cap`], which is controls how much leeway
    /// keyservers have to vary in speed. (larger values were determined to benefit performance
    /// during testing)
    ///
    /// [`Future`]: std::future::Future
    /// [`Stream`]: futures::Stream
    /// [`StreamExt::buffered`]: futures::StreamExt::buffered
    pub parallelism_per_request: NonZeroUsize,
    /// Server-wide limit to the number of crypto steps that can be executed in parallel.
    ///
    /// See [`parallelism_per_request`](Self::parallelism_per_request) for details.
    pub server_parallelism_limit: Arc<Semaphore>,
}

impl<S> DoprfConfig<'_, S> {
    fn client_config(&self) -> ClientConfig {
        ClientConfig {
            api_client: self.api_client.clone(),
            certs: self.params.certs.clone(),
            version_hint: self.version_hint.clone(),
        }
    }

    pub fn nucleotide_total_count<N>(&self) -> Result<u64, DoprfError>
    where
        S: AsRef<[N]>,
    {
        self.sequences
            .iter()
            .map(|seq| seq.as_ref().len())
            .try_fold(0u64, |total, len| total.checked_add(len.try_into().ok()?))
            .ok_or(DoprfError::SequencesTooBig)
    }
}

#[derive(Debug)]
pub struct DoprfOutput {
    /// The number of hashes sent to the HDB
    pub n_hashes: u64,
    /// True iff all sequences are shorter than the minimum length demanded by the hash spec.
    pub too_short: bool,
    // The consolidation returned from the HDB, possibly with signature
    pub response: HdbScreeningResult,
}

impl DoprfOutput {
    fn too_short() -> Self {
        Self {
            n_hashes: 0,
            too_short: true,
            response: HdbScreeningResult::blank(),
        }
    }

    fn empty() -> Self {
        Self {
            n_hashes: 0,
            too_short: false,
            response: HdbScreeningResult::blank(),
        }
    }
}

/// An internal struct representing the result of the windowing step of DOPRF.
#[derive(Debug)]
struct DoprfWindows<I> {
    /// Total window count.
    count: u64,
    /// Combined windows from the supplied sequences.
    combined_windows: I,
}

impl DoprfWindows<()> {
    /// Turn a sequence into hashable windows.
    fn create<N: ToNucleotideLike + Copy, S: AsRef<[N]>>(
        sequences: impl Iterator<Item = S>,
        hash_spec: &HashSpec,
        max_windows: u64,
    ) -> Result<DoprfWindows<impl (Iterator<Item = (String, HashTag)>) + Clone + 'static>, DoprfError>
    {
        // gah, I didn't think this through... oh well, temporary hack it is
        let sequences = sequences.map(|seq| seq.as_ref().to_vec());
        let windows = OrderWindows::from_sequences(sequences, hash_spec)?;

        let Some(n_windows) = windows.size_hint().1 else {
            // `OrderWindows::size_hint` returns `None` in its second element if
            // (and only if) there are more windows than fit in a `usize`.
            return Err(DoprfError::SequencesTooBig);
        };
        let Ok(n_windows) = u64::try_from(n_windows) else {
            // 128-bit architectures are rare, but let's not leave a footgun lying around.
            return Err(DoprfError::SequencesTooBig);
        };
        if n_windows > max_windows {
            return Err(DoprfError::SequencesTooBig);
        }

        let mut last_record = usize::MAX; // records start at 0, so this makes the first one new
        let combined_windows = windows.map(move |window| match window {
            OrderWindow::Real {
                record,
                htd_index,
                range,
                data,
            } => {
                let hash_tag = HashTag::new(last_record != record, htd_index, range.start);
                last_record = record;
                (data, hash_tag)
            }
            OrderWindow::Dummy { record } => {
                last_record = record;
                (String::new(), HashTag::dummy())
            }
        });

        Ok(DoprfWindows {
            count: n_windows,
            combined_windows,
        })
    }
}

struct DoprfClient<'a, S> {
    config: DoprfConfig<'a, S>,
    nucleotide_total_count: u64,
    keyserver_id_set: KeyserverIdSet,
    keyservers: Vec<(SelectedKeyserver, Option<u64>)>,
    active_security_key: ActiveSecurityKey,
    hdb_client: HdbClient,
}

impl<'a, S> DoprfClient<'a, S> {
    /// Given a DOPRF config, select keyservers and a hdbserver, and open
    /// a connection to the HDB.
    async fn open(
        config: DoprfConfig<'a, S>,
        nucleotide_total_count: u64,
    ) -> Result<Self, DoprfError> {
        // if either of these return an error, then a refresh is required by whoever holds the server selector
        // not our problem! they need to check DoprfError::SelectionRefreshRequired
        let ChosenSelectionSubset {
            keyserver_threshold: _,
            active_security_key,
            keyservers,
            hdb,
        } = config.server_selector.clone().choose().await?;

        let keyserver_id_set: KeyserverIdSet =
            keyservers.iter().map(|ks| ks.id).collect::<Vec<_>>().into();

        info!(
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

        let keyservers = {
            let mut v = Vec::with_capacity(keyservers.len());
            for keyserver in keyservers {
                let last_server_version = config
                    .server_version_handler
                    .get_server_version(keyserver.domain.clone())
                    .await?;
                v.push((keyserver, last_server_version));
            }
            v
        };

        let last_hdbserver_version = config
            .server_version_handler
            .get_server_version(hdb.domain.clone())
            .await?;

        let client_config = config.client_config();
        let common = ScepClientOpenCommon {
            nucleotide_total_count,
            last_server_version: last_hdbserver_version,
            keyserver_id_set: keyserver_id_set.clone(),
            debug_info: config.params.include_debug_info,
        };

        let hdb_client = HdbClient::open(
            hdb,
            client_config,
            common,
            HdbOpenParams {
                region: config.params.region,
                with_exemption: !config.params.ets.is_empty(),
                verifiable: if config.params.verifiable_screening {
                    VerifiableScreeningRequested::Requested
                } else {
                    VerifiableScreeningRequested::NotRequested
                },
                fasta_sha3_256_hex: config.params.fasta_sha3_256_hex.clone(),
                synthclient_version: config.params.synthclient_version.clone(),
            },
        )
        .await?;

        config
            .server_version_handler
            .set_server_version(hdb_client.domain().to_string(), hdb_client.server_version())
            .await;

        Ok(Self {
            config,
            nucleotide_total_count,
            keyserver_id_set,
            keyservers,
            hdb_client,
            active_security_key,
        })
    }

    fn id(&self) -> &RequestId {
        &self.config.request_ctx.id
    }

    fn sequences_too_short_for_hash_spec<N>(&self) -> bool
    where
        S: AsRef<[N]>,
    {
        match self.hdb_client.state.hash_spec.min_width_bp() {
            Some(min) => self.config.sequences.iter().all(|s| s.as_ref().len() < min),
            None => false,
        }
    }

    async fn connect_to_keyservers(&self) -> Result<KeyserverSetClient, DoprfError> {
        let keyserver_set_client = KeyserverSetClient::open(
            self.keyservers.clone(),
            self.config.client_config(),
            self.nucleotide_total_count,
            self.keyserver_id_set.clone(),
            self.config.params.include_debug_info,
        )
        .await?;

        for client in keyserver_set_client.clients() {
            self.config
                .server_version_handler
                .set_server_version(client.domain().to_string(), client.server_version())
                .await;
        }

        Ok(keyserver_set_client)
    }

    /// Window the given sequences using the hash spec from the current HDB
    /// connection and the configured max window size.
    fn window<N: ToNucleotideLike + Copy, T: AsRef<[N]>>(
        &self,
        sequences: impl Iterator<Item = T>,
    ) -> Result<DoprfWindows<impl (Iterator<Item = (String, HashTag)>) + Clone + 'static>, DoprfError>
    {
        DoprfWindows::create(
            sequences,
            &self.hdb_client.state.hash_spec,
            self.config.max_windows,
        )
    }

    /// Connect to the chosen keyservers to hash the given windows.
    async fn hash(
        &self,
        windows: impl Iterator<Item = (String, HashTag)> + Clone + Send + 'static,
    ) -> Result<
        impl TryStream<
                Ok = (Vec<CompressedCompletedHashValue>, Vec<HashTag>),
                Error = HashingStreamError<DoprfError>,
            > + 'static,
        DoprfError,
    > {
        let ks = self.connect_to_keyservers().await?;

        #[cfg(not(target_arch = "wasm32"))]
        let executor =
            crate::stream::LimitedParallelism::new(self.config.server_parallelism_limit.clone());
        #[cfg(target_arch = "wasm32")]
        let executor = crate::stream::NoParallelism;

        let completed_hashes =
            HashingConfig::default_for_concurrency(self.config.parallelism_per_request)
                .with_executor(executor)
                .hash(
                    windows,
                    ks.keyserve_fns(),
                    self.active_security_key.clone().into(),
                )
                .await?;

        Ok(completed_hashes)
    }
}

/// Takes a slice of sequences, hashes them, sends them to the keyservers,
/// then sends the results to the hdb, per the DOPRF protocol.
pub async fn process<'a, NLike, SliceN>(
    config: DoprfConfig<'a, SliceN>,
) -> Result<DoprfOutput, DoprfError>
where
    NLike: ToNucleotideLike + Copy + 'a,
    SliceN: AsRef<[NLike]>,
{
    let nucleotide_total_count = config.nucleotide_total_count()?;

    if nucleotide_total_count == 0 {
        info!("{}: all sequences were empty", config.request_ctx.id);
        return Ok(DoprfOutput::too_short());
    }

    let client = DoprfClient::open(config, nucleotide_total_count).await?;

    if client.sequences_too_short_for_hash_spec() {
        return Ok(DoprfOutput::too_short());
    }

    let windows = client.window(client.config.sequences.iter())?;

    if windows.count == 0 {
        info!("{}: didn't generate any windows", client.id());
        return Ok(DoprfOutput::empty());
    }
    info!("{}: generated {} windows", client.id(), windows.count);

    // Normally, if an error occurs during hashing, that'll result in the hashing output stream
    // yielding an error, which gets seen by the HTTP client talking to the HDB, which in turn
    // aborts the request and returns an error. Unfortunately, this means all errors look like
    // HDB errors. We might in theory be able to extract the original hashing error from the HDB
    // error if me made assumptions about the HTTP client, but it's easier and more flexible to
    // directly intercept the original errors from the output streams, and then check if a
    // hashing error occurred whenever the HDB reports a problem.
    let error = Arc::new(Mutex::new(None));
    let hashing_error = error.clone();
    let ets_hashing_error = error.clone();

    let window_hashes = client
        .hash(windows.combined_windows)
        .await?
        .map_ok(|(hashes, tags)| {
            hashes
                .into_iter()
                .zip(tags)
                .map(|(hash, tag)| TaggedHash { hash, tag })
                .collect::<Vec<_>>()
        })
        .map_err(move |err| {
            hashing_error.lock().unwrap().get_or_insert(err);
            "placeholder hashing error"
        });

    let ets = &client.config.params.ets;
    let et_windows = client.window(ets.iter().flat_map(|w| w.et.token.dna_sequences()))?;
    let et_hashes = client
        .hash(et_windows.combined_windows)
        .await?
        .map_ok(|(hashes, _tags)| hashes)
        .map_err(move |err| {
            ets_hashing_error.lock().unwrap().get_or_insert(err);
            "placeholder ets hashing error"
        });
    let now = get_now();

    let response = client
        .hdb_client
        .query(
            window_hashes,
            windows.count,
            ets,
            et_hashes,
            et_windows.count,
        )
        .await
        .map_err(move |err| match error.lock().unwrap().take() {
            Some(hashing_err) => hashing_err.into(),
            None => err,
        })?;
    let hdb_duration = now.elapsed();
    debug!("Querying HDB done. Took: {:.2?}", hdb_duration);

    Ok(DoprfOutput {
        n_hashes: windows.count,
        too_short: false,
        response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::time::Duration;

    use quickdna::{BaseSequence, DnaSequence, FastaContent, Nucleotide};
    use sha3::{Digest, Sha3_256};

    use crate::server_selection::test_utils::{
        make_test_selection, make_test_selector, peek_selector_selection,
    };
    use crate::server_selection::{
        ServerEnumerationSource, ServerSelectionConfig, ServerSelectionError,
    };
    use http_client::service::util::ServiceFn;
    use shared_types::requests::RequestId;

    #[tokio::test]
    async fn test_bad_mark_applied() {
        // set up every request to fail (retriably)
        let mock_api_client = BaseApiClient::from(ServiceFn(|_request| async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let response = http::Response::builder()
                .status(429)
                .body("too many requests".to_owned())
                .unwrap();
            Ok::<_, Infallible>(response)
        }));

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

        let fasta = "atcgatcgatcgatcgatcg";
        let dna = DnaSequence::<Nucleotide>::parse(0, fasta).unwrap();
        let json_body = format!(r#"{{"fasta":{fasta:?}}}"#);
        let fasta_sha3_256_hex = hex::encode(Sha3_256::new().chain_update(json_body).finalize());

        // take a first spin
        process(DoprfConfig {
            api_client: &mock_api_client,
            server_selector: selector.clone(),
            request_ctx: &request_ctx,
            sequences: &[dna.as_slice()],
            max_windows: u64::MAX,
            version_hint: "test".to_owned(),
            server_version_handler: &Default::default(),
            params: ScreeningParams {
                certs: certs.clone(),
                region: Region::All,
                include_debug_info: false,
                verifiable_screening: false,
                ets: vec![],
                fasta_sha3_256_hex,
                synthclient_version: "test".to_owned(),
            },
            parallelism_per_request: NonZeroUsize::MIN, // 1
            server_parallelism_limit: Arc::new(Semaphore::new(1)),
        })
        .await
        .unwrap_err();

        let selection = peek_selector_selection(&selector).await;
        // The hdb should be marked bad, since it's telling us it's a teapot.
        assert_eq!(selection.available_hdbs(), 0);
        // The keyservers should not be marked bad, since they weren't reached.
        assert_eq!(selection.available_keyservers(), 3);

        // trying to choose should fail, since the hdb is bad, and the fixed DNS is empty
        assert!(matches!(
            selector.choose().await.unwrap_err(),
            ServerSelectionError::NoQuorum(_),
        ));
    }
}
