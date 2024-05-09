// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use crate::error::DoprfError;
use crate::instant::get_now;
use crate::operations::{incorporate_responses_and_hash, make_keyserver_querysets};
use crate::scep_client::{ClientConfig, HdbClient, KeyserverSetClient};
use crate::server_selection::{ChosenSelectionSubset, SelectedKeyserver, ServerSelector};
use crate::server_version_handler::LastServerVersionHandler;
use crate::windows::Windows;
use certificates::{ExemptionListTokenGroup, TokenBundle};
use doprf::active_security::ActiveSecurityKey;
use doprf::party::KeyserverIdSet;
use doprf::prf::Query;
use doprf::tagged::{HashTag, TaggedHash};
use http_client::BaseApiClient;
use packed_ristretto::{PackableRistretto, PackedRistrettos};
use quickdna::ToNucleotideLike;
use scep_client_helpers::ClientCerts;
use shared_types::hash::HashSpec;
use shared_types::hdb::HdbScreeningResult;
use shared_types::requests::RequestId;
use shared_types::synthesis_permission::Region;
use shared_types::{debug_with_timestamp, info_with_timestamp, requests::RequestContext};

pub struct DoprfConfig<'a, S> {
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
    /// An exemption list token.
    pub elt: Option<TokenBundle<ExemptionListTokenGroup>>,
    /// A 2FA one-time password for the exemption list token.
    pub otp: Option<String>,
    pub server_version_handler: &'a LastServerVersionHandler,
}

impl<'a, S> DoprfConfig<'a, S> {
    fn client_config(&self) -> ClientConfig {
        ClientConfig {
            api_client: self.api_client.clone(),
            certs: self.certs.clone(),
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
    /// The consolidation returned from the HDB
    pub response: HdbScreeningResult,
}

impl DoprfOutput {
    fn too_short() -> DoprfOutput {
        Self {
            n_hashes: 0,
            too_short: true,
            response: HdbScreeningResult::default(),
        }
    }
}

/// An internal struct representing the result of the windowing step of DOPRF.
#[derive(Debug)]
struct DoprfWindows {
    /// Total window count.
    count: u64,
    /// Combined windows from the supplied sequences.
    combined_windows: Vec<(HashTag, String)>,
    /// The indices of records that generated at least one window.
    /// These are used to fix up the indices returned by the HDB.
    non_empty_records: Vec<u64>,
}

impl DoprfWindows {
    /// Turn a sequence into hashable windows.
    fn create<N: ToNucleotideLike + Copy, S: AsRef<[N]>>(
        sequences: impl Iterator<Item = S>,
        hash_spec: &HashSpec,
        max_windows: u64,
    ) -> Result<Self, DoprfError> {
        let window_iters = sequences
            .map(|seq| Windows::from_dna(seq.as_ref().iter().copied(), hash_spec))
            .collect::<Result<Vec<_>, _>>()?;

        let n_windows = window_iters
            .iter()
            .map(|iter| iter.size_hint().1)
            .try_fold(0u64, |total, len| total.checked_add(len?.try_into().ok()?))
            .ok_or(DoprfError::SequencesTooBig)?;

        if n_windows > max_windows {
            return Err(DoprfError::SequencesTooBig);
        }

        // Allows us to assume the next `as u64` will always work.
        if u64::try_from(window_iters.len()).is_err() {
            return Err(DoprfError::SequencesTooBig);
        }

        let non_empty_records: Vec<u64> = window_iters
            .iter()
            .enumerate()
            .filter_map(|(record, iter)| (iter.size_hint().0 > 0).then_some(record as u64))
            .collect();

        let combined_windows: Vec<(HashTag, String)> = window_iters.into_iter().flatten().collect();

        Ok(DoprfWindows {
            count: n_windows,
            combined_windows,
            non_empty_records,
        })
    }
}

struct DoprfClient<'a, S> {
    config: DoprfConfig<'a, S>,
    nucleotide_total_count: u64,
    keyserver_id_set: KeyserverIdSet,
    keyservers: Vec<(SelectedKeyserver, Option<u64>)>,
    keyserver_threshold: u32,
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
            keyserver_threshold,
            active_security_key,
            keyservers,
            hdb,
        } = config.server_selector.clone().choose().await?;

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

        let hdb_client = HdbClient::open(
            hdb,
            config.client_config(),
            nucleotide_total_count,
            last_hdbserver_version,
            keyserver_id_set.clone(),
            config.region,
            config.elt.is_some(),
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
            keyserver_threshold,
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
    ) -> Result<DoprfWindows, DoprfError> {
        DoprfWindows::create(
            sequences,
            &self.hdb_client.state.hash_spec,
            self.config.max_windows,
        )
    }

    /// Connect to the chosen keyservers to hash the given windows.
    async fn hash<R>(&self, windows: &DoprfWindows) -> Result<PackedRistrettos<R>, DoprfError>
    where
        R: From<TaggedHash> + PackableRistretto + 'static,
        <R as PackableRistretto>::Array: Send + 'static,
    {
        if windows.combined_windows.is_empty() {
            return Ok(PackedRistrettos::new(vec![]));
        }

        // add one for active security checksum
        let hash_total_count = windows
            .count
            .checked_add(1)
            .ok_or(DoprfError::SequencesTooBig)?;

        let querystate = make_keyserver_querysets(
            self.config.request_ctx,
            &windows.combined_windows,
            self.keyserver_threshold as usize,
            &self.active_security_key,
        );

        let ks = self.connect_to_keyservers().await?;

        // query keyservers with initial hash to get keyserver response querysets of hashes
        let now = get_now();
        let querystate_ristrettos = PackedRistrettos::<Query>::from(&querystate);
        let keyserver_responses = ks.query(hash_total_count, &querystate_ristrettos).await?;
        let querying_duration = now.elapsed();
        debug_with_timestamp!("Querying key servers done. Took: {:.2?}", querying_duration);

        incorporate_responses_and_hash(self.config.request_ctx, querystate, keyserver_responses)
            .await
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
        info_with_timestamp!("{}: all sequences were empty", config.request_ctx.id);
        return Ok(DoprfOutput::too_short());
    }

    let client = DoprfClient::open(config, nucleotide_total_count).await?;

    if client.sequences_too_short_for_hash_spec() {
        return Ok(DoprfOutput::too_short());
    }

    let windows = client.window(client.config.sequences.iter())?;

    if windows.count == 0 {
        info_with_timestamp!("{}: didn't generate any windows", client.id());
        return Ok(DoprfOutput {
            n_hashes: 0,
            too_short: false,
            response: HdbScreeningResult::default(),
        });
    }

    info_with_timestamp!("{}: generated {} windows", client.id(), windows.count);
    let hashes = client.hash(&windows).await?;

    let mut response = match &client.config.elt {
        Some(elt) => {
            let elt_windows = client.window(elt.token.dna_sequences())?;
            let elt_hashes = client.hash(&elt_windows).await?;
            let otp = client.config.otp.unwrap_or_default();
            let now = get_now();
            let response = client
                .hdb_client
                .query_with_elt(&hashes, elt, elt_hashes, otp)
                .await?;
            let hdb_duration = now.elapsed();
            debug_with_timestamp!("Querying HDB done. Took: {:.2?}", hdb_duration);
            response
        }
        None => {
            let now = get_now();
            let response = client.hdb_client.query(&hashes).await?;
            let hdb_duration = now.elapsed();
            debug_with_timestamp!("Querying HDB done. Took: {:.2?}", hdb_duration);
            response
        }
    };

    // The HDB sets `record` based on how many new-record flags it has encountered, but
    // sufficiently small FASTA records won't produce windows, so the `record`s returned
    // by the HDB need to be fixed up to account for records without windows.
    for hazard in &mut response.results {
        hazard.record = *usize::try_from(hazard.record)
            .ok()
            .and_then(|hdb_record| windows.non_empty_records.get(hdb_record))
            .ok_or(DoprfError::InvalidRecord)?;
    }

    Ok(DoprfOutput {
        n_hashes: windows.count,
        too_short: false,
        response,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    use futures::FutureExt;
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
                    Err(http_client::error::HttpError::RequestError {
                        ctx: url,
                        status: Some(418),
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
        process(DoprfConfig {
            api_client: &mock_api_client,
            server_selector: selector.clone(),
            request_ctx: &request_ctx,
            certs: certs.clone(),
            region: Region::All,
            debug: false,
            sequences: &[dna.as_slice()],
            max_windows: u64::MAX,
            version_hint: "test".to_owned(),
            elt: None,
            otp: None,
            server_version_handler: &Default::default(),
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
