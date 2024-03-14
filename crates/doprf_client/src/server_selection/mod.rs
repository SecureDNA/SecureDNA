// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use futures::{stream::FuturesUnordered, StreamExt};
use rand::seq::IteratorRandom;
use serde::de::DeserializeOwned;

use crate::{
    error::DOPRFError,
    instant::{get_now, Instant},
    retry_if,
    server_selection::dns::*,
};
use doprf::{active_security::ActiveSecurityKey, party::KeyserverId};
use http_client::BaseApiClient;
use shared_types::{
    info_with_timestamp,
    server_selection::{
        HdbQualificationResponse, KeyserverQualificationResponse, QualificationRequest, Role, Tier,
    },
};

pub mod bad_flag;
pub mod dns;
mod refreshable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSelectionConfig {
    /// How to enumerate servers for selection
    pub enumeration_source: ServerEnumerationSource,
    /// How long a selection should last before being refreshed in the background. If none, selections are
    /// never automatically refreshed (but may still be background refreshed in case of error).
    pub soft_timeout: Option<Duration>,
    /// How long a selection should last before requests MUST wait until refresh finishes.
    /// If None, this behavior is not enforced, and the selection will only be blocking-refreshed
    /// in case of error.
    pub blocking_timeout: Option<Duration>,
    /// A soft (background) refresh will be triggered if there are fewer keyservers with at least one good replica
    /// in a selection than this value + the keyserver threshold. For example, if this value was 2 and the keyserver
    /// threshold was 3, then a soft refresh would be triggered for fewer than 5 good keyservers.
    /// If None, a soft refresh will never be triggered based on a lack of good keyservers (a hard refresh will
    /// still be triggered if there aren't enough keyservers to meet quorum.)
    pub soft_extra_keyserver_threshold: Option<u32>,
    /// A soft (background) refresh will be triggered if there are fewer good HDBs in a selection
    /// than this value + 1. For example, if this value was 2, then a soft refresh would be triggered
    /// if there was less than 3 good HDBs.
    /// If None, a soft refresh will never be triggered based on a lack of good keyservers (a hard refresh will
    /// still be triggered if there aren't enough keyservers to meet quorum.)
    pub soft_extra_hdb_threshold: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEnumerationSource {
    #[cfg(not(target_arch = "wasm32"))]
    NativeDns { tier: Tier, apex: String },
    DnsOverHttps {
        provider_domain: String,
        tier: Tier,
        apex: String,
    },
    Fixed {
        keyserver_domains: Vec<String>,
        hdb_domains: Vec<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerSelection {
    /// What db/keyserver generation this selection landed on
    pub generation: u32,
    /// Number of keyservers that need to be contacted
    pub keyserver_threshold: u32,
    /// Map from known ids to keyservers with that id—if multiple keyservers are available
    /// under an id, they should be treated as replicas
    pub keyservers: HashMap<KeyserverId, Vec<SelectedKeyserver>>,
    /// Active security key for the qualified keyservers, which can be
    /// used with any subset of `self.keyservers`
    pub active_security_key: ActiveSecurityKey,
    /// List of available hdbs (all hdbs are identical for a given generation)
    pub hdbs: Vec<SelectedHdb>,
}

/// A chosen subset of the selection meeting the quorum.
///
/// Do not implement `Clone` for this type—it's important that the `bad_flag` references
/// are kept the same for interior mutability.
#[derive(Debug, PartialEq, Eq)]
pub struct ChosenSelectionSubset {
    pub keyserver_threshold: u32,
    pub active_security_key: ActiveSecurityKey,
    pub keyservers: Vec<SelectedKeyserver>,
    pub hdb: SelectedHdb,
}

impl ServerSelection {
    /// Choose `keyserver_threshold` keyservers from the selected quorum.
    ///
    /// This returns None if not enough good (not marked bad due to returning errors) servers
    /// are available. In that case, the selection must be refreshed.
    fn choose_n_keyservers(&self) -> Option<Vec<&SelectedKeyserver>> {
        let threshold = self.keyserver_threshold as usize;

        let keyservers: Vec<&SelectedKeyserver> = self
            .keyservers
            .values()
            .filter_map(|replicas| match &**replicas {
                [] => None,
                [replica] => {
                    if replica.bad_flag.is_bad() {
                        None
                    } else {
                        Some(replica)
                    }
                }
                replicas => replicas
                    .iter()
                    .filter(|replica| !replica.bad_flag.is_bad())
                    .choose(&mut rand::thread_rng()),
            })
            .choose_multiple(&mut rand::thread_rng(), threshold);

        if keyservers.len() == threshold {
            Some(keyservers)
        } else {
            None
        }
    }

    /// Choose an hdb from the quorum.
    ///
    /// This returns None if not enough good (not marked bad due to returning errors) servers
    /// are available. In that case, the selection must be refreshed.
    fn choose_hdb(&self) -> Option<&SelectedHdb> {
        self.hdbs
            .iter()
            .filter(|hdb| !hdb.bad_flag.is_bad())
            .choose(&mut rand::thread_rng())
    }

    /// Choose a subset from the current selection.
    ///
    /// This returns None if not enough good (not marked bad due to returning errors) servers
    /// are available. In that case, the selection must be refreshed.
    fn choose(&self) -> Option<ChosenSelectionSubset> {
        let keyservers = self.choose_n_keyservers()?.into_iter().cloned().collect();
        let hdb = self.choose_hdb()?.clone();
        Some(ChosenSelectionSubset {
            keyserver_threshold: self.keyserver_threshold,
            active_security_key: self.active_security_key.clone(),
            keyservers,
            hdb,
        })
    }

    /// Returns the count of good (not marked bad due to returning errors) keyservers
    /// in this selection.
    pub fn available_keyservers(&self) -> usize {
        self.keyservers
            .values()
            .filter(|replicas| replicas.iter().any(|r| !r.bad_flag.is_bad()))
            .count()
    }

    /// Returns the count of good (not marked bad due to returning errors) hdbs
    /// in this selection.
    pub fn available_hdbs(&self) -> usize {
        self.hdbs
            .iter()
            .filter(|hdb| !hdb.bad_flag.is_bad())
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedKeyserver {
    /// ID of this keyserver (may differ from the number in the domain, in case of gaps or replicas)
    pub id: KeyserverId,
    /// Domain this keyserver lives on
    pub domain: String,
    /// Whether this server has been marked bad, and shouldn't be selected.
    pub bad_flag: bad_flag::ServerBadFlag,
}

impl fmt::Display for SelectedKeyserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Keyserver({}, {:?}, is_bad={})",
            self.id,
            self.domain,
            self.bad_flag.is_bad()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedHdb {
    /// Domain this HDB lives on
    pub domain: String,
    /// Whether this server has been marked bad, and shouldn't be selected.
    pub bad_flag: bad_flag::ServerBadFlag,
}

impl fmt::Display for SelectedHdb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hdb({:?}, is_bad={})",
            self.domain,
            self.bad_flag.is_bad()
        )
    }
}

#[derive(Debug)]
pub struct ServerSelector {
    /// Config for generating and refreshing the current selection
    config: ServerSelectionConfig,
    /// API client for refreshing the selection
    api_client: BaseApiClient,
    /// The current selection and selection time
    current: refreshable::Refreshable<(Arc<ServerSelection>, Instant)>,
}

impl ServerSelector {
    pub async fn new(
        config: ServerSelectionConfig,
        api_client: BaseApiClient,
    ) -> Result<Self, ServerSelectionError> {
        let selection = server_selection(&config, &api_client).await?;
        Ok(Self {
            config,
            api_client,
            current: refreshable::Refreshable::new((Arc::new(selection), get_now())),
        })
    }

    /// Choose a subset from the current selection.
    /// This may involve running a refresh beforehand or firing off a background refresh,
    /// depending on settings.
    pub async fn choose(self: Arc<Self>) -> Result<ChosenSelectionSubset, ServerSelectionError> {
        let (choice, selection, time) = self
            .current
            .accept_or(
                |(selection, time)| {
                    if self.needs_blocking_refresh_for_time(time) {
                        return None;
                    }
                    let choice = selection.choose()?;
                    Some((choice, selection, time))
                },
                || async {
                    info_with_timestamp!("starting blocking refresh");
                    server_selection(&self.config, &self.api_client)
                        .await
                        .map(|selection| (Arc::new(selection), get_now()))
                },
            )
            .await?;

        let needs_soft_refresh = self.needs_soft_refresh_for_time(time)
            || self.needs_soft_refresh_for_server_threshold(&selection);
        if needs_soft_refresh {
            #[cfg(target_arch = "wasm32")]
            info_with_timestamp!(
                "warning: background refresh not implemented for WASM, skipping..."
            );

            #[cfg(not(target_arch = "wasm32"))]
            {
                let this = self.clone();
                tokio::spawn(async move {
                    let r = this
                        .current
                        .background_refresh(|| async {
                            server_selection(&this.config, &this.api_client)
                                .await
                                .map(|selection| (Arc::new(selection), get_now()))
                        })
                        .await;
                    if let Err(e) = r {
                        info_with_timestamp!("error during background refresh: {}", e);
                    }
                });
            }
        }

        Ok(choice)
    }

    fn needs_soft_refresh_for_time(&self, last_selection: Instant) -> bool {
        let Some(soft_timeout) = self.config.soft_timeout else {
            return false;
        };
        last_selection + soft_timeout <= get_now()
    }

    fn needs_soft_refresh_for_server_threshold(&self, last: &ServerSelection) -> bool {
        let needs_for_ks = if let Some(soft_extra_keyserver_threshold) =
            self.config.soft_extra_keyserver_threshold
        {
            let available_keyservers: u32 = last.available_keyservers().try_into().unwrap();
            available_keyservers < soft_extra_keyserver_threshold + last.keyserver_threshold
        } else {
            false
        };

        let needs_for_hdb =
            if let Some(soft_extra_hdb_threshold) = self.config.soft_extra_hdb_threshold {
                let available_hdbs: u32 = last.available_hdbs().try_into().unwrap();
                available_hdbs < soft_extra_hdb_threshold + 1
            } else {
                false
            };

        needs_for_ks || needs_for_hdb
    }

    fn needs_blocking_refresh_for_time(&self, last_selection: Instant) -> bool {
        let Some(blocking_timeout) = self.config.blocking_timeout else {
            return false;
        };
        last_selection + blocking_timeout <= get_now()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServerSelectionError {
    #[error("failed to qualify enumerated servers: {0}")]
    Qualification(String),
    #[error("could not find quorum for any available generation {0:?} (check logs)")]
    NoQuorum(Vec<u32>),
}

/// Do network calls and run the selection algorithm
pub async fn server_selection(
    config: &ServerSelectionConfig,
    api_client: &BaseApiClient,
) -> Result<ServerSelection, ServerSelectionError> {
    info_with_timestamp!("server selection: refreshing...");

    let (keyserver_domains, hdb_domains) = match &config.enumeration_source {
        #[cfg(not(target_arch = "wasm32"))]
        ServerEnumerationSource::NativeDns { tier, apex } => {
            enumerate(NativeDns, *tier, apex).await
        }
        ServerEnumerationSource::DnsOverHttps {
            provider_domain,
            tier,
            apex,
        } => {
            let dns = DnsOverHttps::new(provider_domain);
            enumerate(&dns, *tier, apex).await
        }
        ServerEnumerationSource::Fixed {
            keyserver_domains,
            hdb_domains,
        } => (keyserver_domains.clone(), hdb_domains.clone()),
    };

    let (keyserver_qualifications, hdb_qualifications) = futures::join!(
        qualify::<KeyserverQualificationResponse>(keyserver_domains, api_client),
        qualify::<HdbQualificationResponse>(hdb_domains, api_client),
    );

    let keyservers = keyserver_qualifications
        .into_iter()
        .filter_map(|(domain, q)| match q {
            Ok(d) => Some((domain, d)),
            Err(e) => {
                info_with_timestamp!("server selection: keyserver rejection: {}", e);
                None
            }
        })
        .collect::<Vec<_>>();

    let hdbs = hdb_qualifications
        .into_iter()
        .filter_map(|(domain, q)| match q {
            Ok(d) => Some((domain, d)),
            Err(e) => {
                info_with_timestamp!("server selection: hdb rejection: {}", e);
                None
            }
        })
        .collect::<Vec<_>>();

    // run the selection algorithm
    let selection =
        do_server_selection(keyservers, hdbs).map_err(ServerSelectionError::NoQuorum)?;
    Ok(selection)
}

async fn enumerate(
    dns: impl dns::DnsLookup + Copy,
    tier: Tier,
    apex: &str,
) -> (Vec<String>, Vec<String>) {
    futures::join!(
        enumerate_role(dns, Role::Keyserver, tier, apex),
        enumerate_role(dns, Role::Hdb, tier, apex),
    )
}

async fn enumerate_role(
    dns: impl dns::DnsLookup,
    role: Role,
    tier: Tier,
    apex: &str,
) -> Vec<String> {
    let mut domains = Vec::new();
    loop {
        let domain = format!(
            "{}.{}.{}.{apex}",
            domains.len() + 1,
            role.domain_str(),
            tier.domain_str()
        );
        match dns.lookup(&domain).await {
            Ok(true) => domains.push(domain),
            Ok(false) => break,
            Err(e) => {
                info_with_timestamp!("server selection: got DNS service error during enumeration, stopping early: {}", e);
                break;
            }
        }
    }
    domains
}

async fn qualify<D: DeserializeOwned>(
    domains: Vec<String>,
    api_client: &BaseApiClient,
) -> Vec<(String, Result<D, DOPRFError>)> {
    let tasks = FuturesUnordered::new();
    for domain in domains.into_iter() {
        tasks.push(async {
            let q = qualify_one(&domain, api_client).await;
            (domain, q)
        })
    }
    tasks.collect().await
}

/// Hit the qualification endpoint, returning Ok(resp) if successful, and Err if we are rejected by the server, or run
/// into some other error and our retries run out
async fn qualify_one<D: DeserializeOwned>(
    domain: &str,
    api_client: &BaseApiClient,
) -> Result<D, DOPRFError> {
    let url = format!("https://{domain}/qualification");

    // we don't use our crate's default retry_if policy here because it waits too long--we
    // want qualification to be fast. likewise, we timeout the futures after 10 seconds,
    // since /qualification is just static data. 5s timeout + this policy limits how long
    // we'll try a single server in qualification to ~20s.

    let policy = retry_if::retry_policy_jittered_fibonacci().with_max_retries(3);

    policy
        .retry_if(
            || {
                retry_if::with_timeout(Duration::from_secs(5), async {
                    Ok(api_client
                        .json_json_post(&url, &QualificationRequest { client_version: 0 })
                        .await?)
                })
            },
            // don't retry 400 Bad Request
            |e: &DOPRFError| {
                info_with_timestamp!("qualification for {}: got error: {}", domain, e);
                e.is_retriable()
            },
        )
        .await
}

/// Run the selection algorithm (no network calls happen in this function)
fn do_server_selection(
    keyservers: Vec<(String, KeyserverQualificationResponse)>,
    hdbs: Vec<(String, HdbQualificationResponse)>,
) -> Result<ServerSelection, Vec<u32>> {
    let known_generations = find_available_generations(&keyservers, &hdbs);
    info_with_timestamp!(
        "server selection: found generations {:?}",
        known_generations
    );

    for generation in known_generations.iter().copied() {
        match try_server_selection_for_generation(generation, &keyservers, &hdbs) {
            Ok(selection) => {
                info_with_timestamp!(
                    "server selection: found quorum on generation {}",
                    generation
                );
                return Ok(selection);
            }
            Err(e) => {
                info_with_timestamp!("server selection: skipping generation: {}", e);
            }
        }
    }

    info_with_timestamp!("server selection: FATAL: failed to find quorum on any generation!");
    Err(known_generations)
}

/// get all known generation numbers from the responses, deduplicate them, and reverse sort
/// (so we start with the highest generation and work down)
fn find_available_generations(
    keyservers: &[(String, KeyserverQualificationResponse)],
    hdbs: &[(String, HdbQualificationResponse)],
) -> Vec<u32> {
    let mut generations: Vec<u32> = keyservers
        .iter()
        .flat_map(|(_, r)| r.generations_and_key_info.keys().copied())
        .chain(
            hdbs.iter()
                .flat_map(|(_, r)| r.supported_generations.iter().copied()),
        )
        .collect();
    generations.sort_unstable();
    generations.dedup();
    generations.reverse();
    generations
}

#[derive(Debug, Clone, thiserror::Error)]
enum GenerationSelectionError {
    #[error("no keyservers support generation {generation}")]
    NoKeyserversSupportGeneration { generation: u32 },
    #[error("no hdbs support generation {generation}")]
    NoHdbsSupportGeneration { generation: u32 },
    #[error("keyservers reported different thresholds for generation {generation}: {found_thresholds:?}")]
    MismatchedThresholdForGeneration {
        generation: u32,
        found_thresholds: HashSet<u32>,
    },
    #[error("for generation {generation}, {threshold} keyservers are needed, but only {keyserver_count} were found")]
    NotEnoughKeyserversForThreshold {
        generation: u32,
        threshold: u32,
        keyserver_count: u32,
    },
    #[error("could not select active security key for generation {generation}, error: {error}, received these values and counts {:?}", active_security_key_occurances)]
    NoValidActiveSecurityKey {
        generation: u32,
        active_security_key_occurances: HashMap<ActiveSecurityKey, u32>,
        error: ActiveSecurityKeySelectionError,
    },
}

fn try_server_selection_for_generation(
    generation: u32,
    keyservers: &[(String, KeyserverQualificationResponse)],
    hdbs: &[(String, HdbQualificationResponse)],
) -> Result<ServerSelection, GenerationSelectionError> {
    // first, extract the threshold from the responses, making sure all the keyservers agree
    let threshold = {
        let found_thresholds = keyservers
            .iter()
            .filter_map(|(_, ks_q)| ks_q.generations_and_key_info.get(&generation))
            .map(|key_info| key_info.quorum)
            .collect::<HashSet<_>>();

        match found_thresholds.len() {
            0 => {
                return Err(GenerationSelectionError::NoKeyserversSupportGeneration { generation })
            }
            1 => found_thresholds.into_iter().next().unwrap(),
            // TODO: do we want to handle this more gracefully, like with a majority vote? see wiki
            _ => {
                return Err(GenerationSelectionError::MismatchedThresholdForGeneration {
                    generation,
                    found_thresholds,
                })
            }
        }
    };

    // next, select the keyservers and group replicas by reported id
    let (selected_keyservers, active_security_key_occurances) = {
        let mut selected_keyservers: HashMap<KeyserverId, Vec<SelectedKeyserver>> = HashMap::new();
        let mut active_security_key_occurances: HashMap<ActiveSecurityKey, u32> = HashMap::new();

        for (domain, q) in keyservers {
            if let Some(key_info) = q.generations_and_key_info.get(&generation) {
                selected_keyservers
                    .entry(q.id)
                    .or_default()
                    .push(SelectedKeyserver {
                        id: q.id,
                        domain: domain.clone(),
                        bad_flag: Default::default(),
                    });
                *active_security_key_occurances
                    .entry(key_info.active_security_key.clone())
                    .or_insert(0) += 1;
            }
        }

        (selected_keyservers, active_security_key_occurances)
    };

    // error if we can't reach quorum
    if selected_keyservers.len() < threshold as usize {
        return Err(GenerationSelectionError::NotEnoughKeyserversForThreshold {
            generation,
            threshold,
            keyserver_count: selected_keyservers.len().try_into().unwrap(),
        });
    }

    let active_security_key =
        select_active_security_key(&active_security_key_occurances, threshold).map_err(|err| {
            GenerationSelectionError::NoValidActiveSecurityKey {
                generation,
                active_security_key_occurances,
                error: err,
            }
        })?;

    // select the hdbs that support this generation
    let selected_hdbs = hdbs
        .iter()
        .filter_map(|(domain, q)| {
            if q.supported_generations.contains(&generation) {
                Some(SelectedHdb {
                    domain: domain.clone(),
                    bad_flag: Default::default(),
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    // error if no hdbs do
    if hdbs.is_empty() {
        return Err(GenerationSelectionError::NoHdbsSupportGeneration { generation });
    }

    // hooray!
    Ok(ServerSelection {
        generation,
        keyserver_threshold: threshold,
        keyservers: selected_keyservers,
        active_security_key,
        hdbs: selected_hdbs,
    })
}

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum ActiveSecurityKeySelectionError {
    #[error("required {quorum} matching active security keys")]
    InsufficientMatching { quorum: u32 },
    #[error("insufficient active security keys found supporting a quorum of {quorum}")]
    QuorumMismatch { quorum: u32 },
    #[error("found sufficient qualifying active security keys but did not find a unique majority")]
    NoUniqueMajority,
}

fn select_active_security_key(
    active_security_key_occurances: &HashMap<ActiveSecurityKey, u32>,
    quorum: u32,
) -> Result<ActiveSecurityKey, ActiveSecurityKeySelectionError> {
    let keys_with_sufficient_count: Vec<_> = active_security_key_occurances
        .iter()
        .filter(|(_, count)| *count >= &quorum)
        .collect();

    if keys_with_sufficient_count.is_empty() {
        return Err(ActiveSecurityKeySelectionError::InsufficientMatching { quorum });
    }

    let keys_with_matching_count_and_quorum: Vec<_> = keys_with_sufficient_count
        .into_iter()
        .filter(|(key, _)| key.supported_quorum() == quorum)
        .collect();

    let max_count = keys_with_matching_count_and_quorum
        .iter()
        .map(|(_, count)| *count)
        .max()
        .cloned()
        .ok_or(ActiveSecurityKeySelectionError::QuorumMismatch { quorum })?;

    // collect values that match the maximum count
    let max_values = keys_with_matching_count_and_quorum
        .into_iter()
        .filter(|(_, count)| *count == &max_count)
        .map(|(value, _)| value)
        .collect::<Vec<_>>();

    // check for non-unique majority
    match max_values.len() {
        1 => Ok(max_values.into_iter().next().unwrap().clone()),
        _ => Err(ActiveSecurityKeySelectionError::NoUniqueMajority),
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;

    use doprf::active_security::Commitment;

    /// Make a dummy `Commitment` by hashing the given byte.
    pub fn dummy_commitment(seed: u8) -> Commitment {
        Commitment::hash_from_bytes_for_tests_only(&[seed])
    }

    /// Make a reasonable server selection from a bare config, if you don't care about the details.
    ///
    /// Initializes the selection with:
    /// * generation = 0
    /// * the given threshold
    /// * a keyserver for each entry in `keyserver_defs`, with the given domain str and id.
    ///     + if an id is duplicated, the keyservers are treated as replicas
    ///     + the commitment is `dummy_commitment(1)`
    ///     + bad_flag = false
    /// * an hdb for each entry in `hdb_defs`, with the given domain
    /// * an active_security_key built from all the keyservers dummy commitments
    pub fn make_test_selection(
        keyserver_threshold: u32,
        keyserver_defs: &[(&str, u32)],
        hdb_defs: &[&str],
    ) -> ServerSelection {
        let mut keyservers: HashMap<KeyserverId, Vec<SelectedKeyserver>> = HashMap::new();
        for &(domain, id) in keyserver_defs {
            assert_ne!(id, 0, "can't have ks id 0");
            let id = KeyserverId::try_from(id).unwrap();
            keyservers.entry(id).or_default().push(SelectedKeyserver {
                id,
                domain: domain.to_owned(),
                bad_flag: Default::default(),
            });
        }

        let hdbs: Vec<SelectedHdb> = hdb_defs
            .iter()
            .map(|&domain| SelectedHdb {
                domain: domain.to_owned(),
                bad_flag: Default::default(),
            })
            .collect();

        let commitments: Vec<_> = (0..keyserver_threshold)
            .map(|_| dummy_commitment(1))
            .collect();
        let active_security_key = ActiveSecurityKey::from_commitments(commitments);

        ServerSelection {
            generation: 0,
            keyserver_threshold,
            keyservers,
            hdbs,
            active_security_key,
        }
    }

    /// Make a `ServerSelector` with a specific selection, API client, and config.
    pub fn make_test_selector(
        config: ServerSelectionConfig,
        api_client: BaseApiClient,
        selection: ServerSelection,
        selection_time: Instant,
    ) -> ServerSelector {
        ServerSelector {
            config,
            api_client,
            current: refreshable::Refreshable::new((Arc::new(selection), selection_time)),
        }
    }

    pub async fn peek_selector_selection(selector: &ServerSelector) -> Arc<ServerSelection> {
        async fn unreachable_infail(
        ) -> Result<(Arc<ServerSelection>, Instant), std::convert::Infallible> {
            unreachable!();
        }
        // immediately accept any selection, such that refresh will never be called
        selector
            .current
            .accept_or(|(selection, _)| Some(selection), unreachable_infail)
            .await
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use shared_types::server_selection::KeyInfo;

    use super::test_utils::{dummy_commitment, make_test_selection};
    use super::*;

    use crate::server_selection::dns::test_utils::MockDns;

    #[tokio::test]
    async fn enumerate_normal() {
        let dns = MockDns::new()
            .with_known_domain("1.ks.dev.securedna.org")
            .with_known_domain("2.ks.dev.securedna.org")
            .with_known_domain("3.ks.dev.securedna.org")
            .with_known_domain("5.ks.dev.securedna.org") // hole before, this one should not get reached
            .with_known_domain("0.db.dev.securedna.org") // server with "0" part should never be selected
            .with_known_domain("1.db.dev.securedna.org")
            .with_known_domain("2.db.dev.securedna.org");

        assert_eq!(
            enumerate(&dns, Tier::Dev, "securedna.org").await,
            (
                vec![
                    "1.ks.dev.securedna.org".into(),
                    "2.ks.dev.securedna.org".into(),
                    "3.ks.dev.securedna.org".into(),
                ],
                vec![
                    "1.db.dev.securedna.org".into(),
                    "2.db.dev.securedna.org".into(),
                ]
            ),
        );
    }

    #[tokio::test]
    async fn enumerate_with_errors() {
        let dns = MockDns::new()
            .with_known_domain("1.db.dev.securedna.org")
            .with_known_domain("1.ks.dev.securedna.org")
            .with_known_domain("2.ks.dev.securedna.org")
            .with_error("3.ks.dev.securedna.org", || dns::LookupError::Status(500))
            .with_known_domain("4.ks.dev.securedna.org"); // will never be reached

        assert_eq!(
            enumerate(&dns, Tier::Dev, "securedna.org").await,
            (
                vec![
                    "1.ks.dev.securedna.org".into(),
                    "2.ks.dev.securedna.org".into(),
                ],
                vec!["1.db.dev.securedna.org".into(),],
            )
        )
    }

    #[test]
    fn test_picks_correct_generation() {
        let active_security_key =
            ActiveSecurityKey::from_commitments(vec![dummy_commitment(1), dummy_commitment(2)]);
        let key_info = KeyInfo {
            quorum: 2,
            active_security_key: active_security_key.clone(),
        };
        let result = do_server_selection(
            vec![
                (
                    "1.ks.dev.securedna.org".into(),
                    KeyserverQualificationResponse {
                        id: KeyserverId::try_from(1).unwrap(),
                        generations_and_key_info: [
                            (0, key_info.clone()),
                            (1, key_info.clone()),
                            (2, key_info.clone()),
                        ]
                        .into_iter()
                        .collect(),
                    },
                ),
                (
                    "2.ks.dev.securedna.org".into(),
                    KeyserverQualificationResponse {
                        id: KeyserverId::try_from(2).unwrap(),
                        generations_and_key_info: [
                            (0, key_info.clone()),
                            (1, key_info.clone()),
                            (3, key_info.clone()),
                        ]
                        .into_iter()
                        .collect(),
                    },
                ),
                (
                    "3.ks.dev.securedna.org".into(),
                    KeyserverQualificationResponse {
                        id: KeyserverId::try_from(2).unwrap(),
                        generations_and_key_info: [
                            (0, key_info.clone()),
                            (1, key_info.clone()),
                            (3, key_info.clone()),
                        ]
                        .into_iter()
                        .collect(),
                    },
                ),
            ],
            vec![(
                "1.db.dev.securedna.org".into(),
                HdbQualificationResponse {
                    supported_generations: vec![0, 1],
                },
            )],
        )
        .unwrap();

        assert_eq!(
            result,
            ServerSelection {
                generation: 1,
                keyserver_threshold: 2,
                keyservers: [
                    (
                        KeyserverId::try_from(1).unwrap(),
                        vec![SelectedKeyserver {
                            id: KeyserverId::try_from(1).unwrap(),
                            domain: "1.ks.dev.securedna.org".into(),
                            bad_flag: Default::default(),
                        }]
                    ),
                    (
                        KeyserverId::try_from(2).unwrap(),
                        vec![
                            SelectedKeyserver {
                                id: KeyserverId::try_from(2).unwrap(),
                                domain: "2.ks.dev.securedna.org".into(),
                                bad_flag: Default::default(),
                            },
                            SelectedKeyserver {
                                id: KeyserverId::try_from(2).unwrap(),
                                domain: "3.ks.dev.securedna.org".into(),
                                bad_flag: Default::default(),
                            }
                        ]
                    )
                ]
                .into_iter()
                .collect(),
                active_security_key,
                hdbs: vec![SelectedHdb {
                    domain: "1.db.dev.securedna.org".into(),
                    bad_flag: Default::default(),
                }]
            }
        )
    }

    #[test]
    fn test_picks_correct_generation_with_respect_to_active_security_key_quorum() {
        // AS key supports quorum of 3 (due to commitment count)
        let active_security_key = ActiveSecurityKey::from_commitments(vec![
            dummy_commitment(1),
            dummy_commitment(2),
            dummy_commitment(3),
        ]);
        let bad_key_info = KeyInfo {
            quorum: 2,
            active_security_key: active_security_key.clone(),
        };

        let good_key_info = KeyInfo {
            quorum: 3,
            active_security_key: active_security_key.clone(),
        };

        let result = do_server_selection(
            vec![
                (
                    "1.ks.dev.securedna.org".into(),
                    KeyserverQualificationResponse {
                        id: KeyserverId::try_from(1).unwrap(),
                        generations_and_key_info: [
                            (0, good_key_info.clone()),
                            (1, bad_key_info.clone()),
                        ]
                        .into_iter()
                        .collect(),
                    },
                ),
                (
                    "2.ks.dev.securedna.org".into(),
                    KeyserverQualificationResponse {
                        id: KeyserverId::try_from(2).unwrap(),
                        generations_and_key_info: [
                            (0, good_key_info.clone()),
                            (1, bad_key_info.clone()),
                        ]
                        .into_iter()
                        .collect(),
                    },
                ),
                (
                    "3.ks.dev.securedna.org".into(),
                    KeyserverQualificationResponse {
                        id: KeyserverId::try_from(3).unwrap(),
                        generations_and_key_info: [
                            (0, good_key_info.clone()),
                            (1, bad_key_info.clone()),
                        ]
                        .into_iter()
                        .collect(),
                    },
                ),
            ],
            vec![(
                "1.db.dev.securedna.org".into(),
                HdbQualificationResponse {
                    supported_generations: vec![0, 1],
                },
            )],
        )
        .unwrap();

        assert_eq!(
            result,
            ServerSelection {
                generation: 0,
                keyserver_threshold: 3,
                keyservers: [
                    (
                        KeyserverId::try_from(1).unwrap(),
                        vec![SelectedKeyserver {
                            id: KeyserverId::try_from(1).unwrap(),
                            domain: "1.ks.dev.securedna.org".into(),
                            bad_flag: Default::default(),
                        }]
                    ),
                    (
                        KeyserverId::try_from(2).unwrap(),
                        vec![SelectedKeyserver {
                            id: KeyserverId::try_from(2).unwrap(),
                            domain: "2.ks.dev.securedna.org".into(),
                            bad_flag: Default::default(),
                        }]
                    ),
                    (
                        KeyserverId::try_from(3).unwrap(),
                        vec![SelectedKeyserver {
                            id: KeyserverId::try_from(3).unwrap(),
                            domain: "3.ks.dev.securedna.org".into(),
                            bad_flag: Default::default(),
                        }]
                    )
                ]
                .into_iter()
                .collect(),
                active_security_key,
                hdbs: vec![SelectedHdb {
                    domain: "1.db.dev.securedna.org".into(),
                    bad_flag: Default::default(),
                }]
            }
        )
    }

    #[test]
    fn marking_bad_makes_keyserver_choosing_fail() {
        let selection =
            make_test_selection(2, &[("apple", 1), ("pear", 2), ("peach", 3)], &["hdb"]);

        selection.choose_n_keyservers().unwrap(); // choose 2 from 3 => succeeds

        selection
            .keyservers
            .get(&KeyserverId::try_from(1).unwrap())
            .unwrap()[0]
            .bad_flag
            .mark_bad();

        selection.choose_n_keyservers().unwrap(); // choose 2 from 2 => succeeds

        selection
            .keyservers
            .get(&KeyserverId::try_from(2).unwrap())
            .unwrap()[0]
            .bad_flag
            .mark_bad();

        assert!(selection.choose_n_keyservers().is_none()); // choose 2 from 1 => fails
    }

    #[test]
    fn replicas_used_when_other_marked_bad() {
        let selection =
            make_test_selection(2, &[("apple1", 1), ("apple2", 1), ("orange", 2)], &["hdb"]);

        selection.choose_n_keyservers().unwrap(); // chooses either apple replica

        selection
            .keyservers
            .get(&KeyserverId::try_from(1).unwrap())
            .unwrap()[0]
            .bad_flag
            .mark_bad();

        selection.choose_n_keyservers().unwrap(); // chooses the still-good apple replica

        selection
            .keyservers
            .get(&KeyserverId::try_from(1).unwrap())
            .unwrap()[1]
            .bad_flag
            .mark_bad();

        assert!(selection.choose_n_keyservers().is_none()); // all apples bad, fails
    }

    #[test]
    fn badness_preserved_through_clones() {
        let selection =
            make_test_selection(2, &[("apple1", 1), ("apple2", 1), ("orange", 2)], &["hdb"]);
        let cloned = ServerSelection {
            generation: selection.generation,
            keyserver_threshold: selection.keyserver_threshold,
            keyservers: selection.keyservers.clone(),
            active_security_key: selection.active_security_key.clone(),
            hdbs: selection.hdbs.clone(),
        };

        // both og and cloned are fine
        selection.choose_n_keyservers().unwrap();
        cloned.choose_n_keyservers().unwrap();

        // break og
        selection
            .keyservers
            .get(&KeyserverId::try_from(1).unwrap())
            .unwrap()[0]
            .bad_flag
            .mark_bad();

        selection
            .keyservers
            .get(&KeyserverId::try_from(1).unwrap())
            .unwrap()[1]
            .bad_flag
            .mark_bad();

        // should have broken both og and clone because the interiorly-mutable bad flag is Arc'd
        assert!(selection.choose_n_keyservers().is_none());
        assert!(cloned.choose_n_keyservers().is_none());
    }

    #[test]
    fn active_security_key_selection_errors_on_insufficient_count() {
        let mut values_counts = HashMap::new();
        let key_a = ActiveSecurityKey::from_commitments(vec![
            dummy_commitment(1),
            dummy_commitment(2),
            dummy_commitment(3),
        ]);
        values_counts.extend(vec![(key_a, 2)]);

        let result = select_active_security_key(&values_counts, 3)
            .expect_err("should not select a key where count does not meet quorom");

        let expected_error = ActiveSecurityKeySelectionError::InsufficientMatching { quorum: 3 };
        assert_eq!(result, expected_error)
    }

    #[test]
    fn active_security_key_selection_errors_on_quorom_mismatch_count() {
        let mut values_counts = HashMap::new();
        let key_a =
            ActiveSecurityKey::from_commitments(vec![dummy_commitment(1), dummy_commitment(2)]);
        values_counts.extend(vec![(key_a, 3)]);

        let result = select_active_security_key(&values_counts, 3)
            .expect_err("should not select a key where count does not meet quorom");

        let expected_error = ActiveSecurityKeySelectionError::QuorumMismatch { quorum: 3 };
        assert_eq!(result, expected_error)
    }

    #[test]
    fn active_security_key_selection_errors_on_non_unique_majority() {
        let mut values_counts = HashMap::new();
        let key_a = ActiveSecurityKey::from_commitments(vec![
            dummy_commitment(1),
            dummy_commitment(2),
            dummy_commitment(3),
        ]);
        let key_b = ActiveSecurityKey::from_commitments(vec![
            dummy_commitment(4),
            dummy_commitment(5),
            dummy_commitment(6),
        ]);
        values_counts.extend(vec![(key_a, 3), (key_b, 3)]);

        let result = select_active_security_key(&values_counts, 3)
            .expect_err("should not select a key where count does not meet quorom");

        let expected_error = ActiveSecurityKeySelectionError::NoUniqueMajority;
        assert_eq!(result, expected_error)
    }

    #[test]
    fn active_security_key_selection_can_select_correct_key() {
        let mut values_counts = HashMap::new();
        let key_a = ActiveSecurityKey::from_commitments(vec![
            dummy_commitment(1),
            dummy_commitment(2),
            dummy_commitment(3),
        ]);
        let key_b =
            ActiveSecurityKey::from_commitments(vec![dummy_commitment(4), dummy_commitment(5)]);
        let key_c = ActiveSecurityKey::from_commitments(vec![
            dummy_commitment(6),
            dummy_commitment(7),
            dummy_commitment(8),
        ]);
        values_counts.extend(vec![(key_a, 2), (key_b, 3), (key_c.clone(), 3)]);

        let result =
            select_active_security_key(&values_counts, 3).expect("selection should succeed");

        assert_eq!(result, key_c)
    }
}
