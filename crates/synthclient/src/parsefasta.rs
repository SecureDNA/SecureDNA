// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cmp::min;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use doprf_client::ScreeningParams;
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::info;

use crate::{
    api::{ApiResponse, HitOrganism},
    retry_if::retry_if,
};
use doprf_client::{
    DoprfConfig, RequestStreaming, error::DoprfError, server_selection::ServerSelector,
    server_version_handler::LastServerVersionHandler, windows::WindowsError,
};
use hdb_api::Organism;
use http_client::BaseApiClient;
use quickdna::{
    BaseSequence, DnaSequence, FastaFile, FastaParseError, FastaParseSettings, FastaParser,
    FastaRecord, Located, NucleotideLike, TranslationError,
};
use shared_types::metrics::SynthClientMetrics;
use shared_types::requests::{RequestContext, RequestId};

#[derive(Debug, Error)]
pub enum CheckFastaError {
    #[error("Invalid FASTA contents: {0}")]
    InvalidInput(#[source] Located<FastaParseError<TranslationError>>),
    #[error("FASTA contains no records")]
    NoRecords,
    #[error("Record {0} is empty")]
    EmptyRecord(String),
    #[error("Failed to make DNA windows: {0}")]
    WindowError(#[from] WindowsError),
    #[error("Internal DOPRF error: {0}")]
    DoprfError(#[from] DoprfError),
    #[error("Request size too big: {0}bp. Max request size: {1}bp")]
    RequestSizeTooBig(usize, usize),
    #[error("Temporary memory limits reached: {0}bp. Max system size: {1}bp")]
    TemporaryMemoryLimitsReached(usize, usize),
}

#[derive(Default)]
pub struct CurrentSystemLoadTracker {
    pub current_base_pair_counter: AtomicUsize,
}

impl From<Organism> for HitOrganism {
    fn from(value: Organism) -> Self {
        Self {
            name: value.name,
            organism_type: value.organism_type,
            ans: value.ans,
            tags: value.tags,
        }
    }
}

pub struct CheckerConfiguration<'a> {
    pub api_client: BaseApiClient,
    pub request_streaming: RequestStreaming,
    pub server_selector: Arc<ServerSelector>,
    pub metrics: Option<Arc<SynthClientMetrics>>,
    pub limit_config: LimitConfiguration<'a>,
    /// `version_hint` we will pass to doprf_client
    pub synthclient_version_hint: &'a str,
    pub server_version_handler: LastServerVersionHandler,
    pub params: ScreeningParams,
    pub provider_reference: Option<String>,
    pub parallelism_per_request: NonZeroUsize,
    pub server_parallelism_limit: Arc<Semaphore>,
}

pub struct LimitConfiguration<'a> {
    pub memory_limit: Option<usize>,
    pub max_request_bp: usize,
    pub limits: &'a CurrentSystemLoadTracker,
}

pub fn parse_fasta<T: NucleotideLike>(
    order_fasta: &str,
) -> Result<FastaFile<DnaSequence<T>>, Located<FastaParseError<TranslationError>>> {
    // allow_preceding_comment MUST be `false` to match our spec:
    // Any text present in the input before the first header line treated as if it is sequence data; it is not ignored.
    // In other words, in this case, the very first record MAY have zero header lines associated with it.
    // Some FASTA files appear to treat this as a comment, but we cannot,
    // because we have no guarantee that all providers will do so.
    // Any provider which treated a headerless sequence as a synthesis request could therefore allow a trivial screening bypass if we ignored this text;
    // customers with such files SHOULD be encouraged to fix them via the provider checking their input and complaining before attempting to screen.

    // concatenate_headers is expected to be `true` in our spec:
    // Multiple header lines MAY appear with no intervening sequence;
    // if so, they are treated as if all of them describe the following sequence.

    let parser = FastaParser::<DnaSequence<T>>::new(
        FastaParseSettings::new()
            .concatenate_headers(true)
            .allow_preceding_comment(false),
    );

    parser.parse_str(order_fasta)
}

/// Takes in a FASTA and compares the DNA to the hazard database.
pub async fn check_fasta<T: NucleotideLike>(
    request_id: &RequestId,
    order_fasta: String,
    config: &CheckerConfiguration<'_>,
) -> Result<ApiResponse, CheckFastaError> {
    let fasta_file = parse_fasta::<T>(&order_fasta).map_err(|located| {
        match located.error {
            // api issue with quickdna, we're parsing a string here
            FastaParseError::IOError(_) => unreachable!("io error reading from str"),
            FastaParseError::ParseError(_) => CheckFastaError::InvalidInput(located),
        }
    })?;

    let _memory_check_tracker = check_system_limits(&config.limit_config, &fasta_file.records)?;
    check_parsed_fasta(request_id, fasta_file, config).await
}

/// RAII class for automatically decrementing the atomic counter when the tracker goes out of scope
struct RAIIAtomic<'a> {
    counter: &'a AtomicUsize,
    size: usize,
}

impl RAIIAtomic<'_> {
    /// Acquire a RAII tracker and increase the atomic `counter` by `size`
    /// Returns the current value along with the RAII tracker
    pub fn acquire(counter: &AtomicUsize, size: usize) -> (usize, RAIIAtomic<'_>) {
        let previous_value = counter.fetch_add(size, Ordering::Relaxed);

        let atomic = RAIIAtomic { counter, size };
        let expected_current_value = previous_value + size;
        (expected_current_value, atomic)
    }
}
impl Drop for RAIIAtomic<'_> {
    fn drop(&mut self) {
        // `Relaxed` here is safe since we dont reason about the value of counter.
        // If this ever had any logic for when the counter reaches `0`,
        // it would have to be changed to `AcqRel`
        self.counter.fetch_sub(self.size, Ordering::Relaxed);
    }
}

/// Checks the system memory limits based on system configuration
/// Returns a `RAIIAtomic` tracker which should be kept around as long as the FASTA is being processed
fn check_system_limits<'a, T: NucleotideLike>(
    limit_config: &'a LimitConfiguration,
    fasta_records: &[FastaRecord<DnaSequence<T>>],
) -> Result<RAIIAtomic<'a>, CheckFastaError> {
    let largest_request = fasta_records
        .iter()
        .map(|record| record.contents.len())
        .max()
        .ok_or(CheckFastaError::NoRecords)?;

    // Limit 1: Transfer Limit to HDB/KS
    // the payload limit for HDB and KSs is 1M BPs (or 128MiB)
    // payloads larger than that will get rejected by the servers
    let mut limit = limit_config.max_request_bp;

    if let Some(memory_limit) = limit_config.memory_limit {
        // Limit 2: Configured synthclient memory limit
        // measurements have shown that we consume roughly 2KiB per BP
        let limit_in_bps = memory_limit / 1024 / 2;
        limit = min(limit, limit_in_bps);
    }

    if largest_request > limit {
        return Err(CheckFastaError::RequestSizeTooBig(largest_request, limit));
    }

    let combined_size = fasta_records.iter().map(|r| r.contents.len()).sum();

    let (proposed_memory, tracker) = RAIIAtomic::acquire(
        &limit_config.limits.current_base_pair_counter,
        combined_size,
    );

    if proposed_memory > limit {
        return Err(CheckFastaError::TemporaryMemoryLimitsReached(
            combined_size,
            limit,
        ));
    }

    Ok(tracker)
}

pub async fn check_parsed_fasta<T: NucleotideLike>(
    request_id: &RequestId,
    fasta_file: FastaFile<DnaSequence<T>>,
    config: &CheckerConfiguration<'_>,
) -> Result<ApiResponse, CheckFastaError> {
    let request_ctx = RequestContext {
        id: request_id.clone(),
        total_records: fasta_file.records.len(),
    };
    let records = fasta_file.records;

    if let Some(record) = records.iter().find(|r| r.contents.is_empty()) {
        return Err(CheckFastaError::EmptyRecord(record.header.clone()));
    }

    // Stolen from check_system_limits... This is an empirical fudge factor
    // that's woefully out-of-date, but it at least allows SOME sort of limit
    // to be applied to total wobble expansions across the whole record.
    let max_windows = config
        .limit_config
        .memory_limit
        .and_then(|max_mem| (max_mem / 2 / 1024).try_into().ok())
        .unwrap_or(u64::MAX);

    let sequences: Vec<_> = records.iter().map(|record| &record.contents).collect();
    let output = retry_if(
        || {
            doprf_client::process(DoprfConfig {
                api_client: &config.api_client,
                server_selector: config.server_selector.clone(),
                request_ctx: &request_ctx,
                sequences: &sequences,
                max_windows,
                version_hint: config.synthclient_version_hint.to_owned(),
                server_version_handler: &config.server_version_handler,
                params: config.params.clone(),
                parallelism_per_request: config.parallelism_per_request,
                server_parallelism_limit: config.server_parallelism_limit.clone(),
                request_streaming: config.request_streaming,
            })
        },
        |err: &DoprfError| {
            if err.is_retriable() {
                info!("{request_ctx}: retrying after error: {err}");

                true
            } else {
                false
            }
        },
    )
    .await
    .map_err(|e| {
        info!("{request_ctx}: internal DOPRF error: {e}");
        e
    })?;

    Ok(ApiResponse::from_doprf_output(
        output,
        &records,
        &config.metrics,
        &config.params,
        config.provider_reference.clone(),
    )?)
}

#[cfg(test)]
mod tests {
    use quickdna::{DnaSequence, FastaParseSettings, FastaParser, Nucleotide};
    use std::sync::atomic::Ordering;

    use crate::parsefasta::{
        CheckFastaError, CurrentSystemLoadTracker, LimitConfiguration, RAIIAtomic,
        check_system_limits,
    };

    fn assert_fasta_within_limits(
        fasta: &str,
        memory_limit: Option<usize>,
        expected_failure: bool,
        expected_request_limit: Option<usize>,
    ) {
        let parser = FastaParser::<DnaSequence<Nucleotide>>::new(
            FastaParseSettings::new()
                .concatenate_headers(true)
                .allow_preceding_comment(false),
        );

        let fastas = parser.parse_str(fasta).unwrap();

        match check_system_limits(
            &LimitConfiguration {
                memory_limit,
                max_request_bp: 1_000_000,
                limits: &Default::default(),
            },
            &fastas.records,
        ) {
            Ok(_) => {
                assert!(!expected_failure, "Unexpected success!");
            }
            Err(err) => {
                assert!(expected_failure, "Unexpected failure!");
                if let Some(check_limit) = expected_request_limit
                    && let CheckFastaError::RequestSizeTooBig(_, request_limit) = err
                {
                    assert_eq!(request_limit, check_limit)
                }
            }
        }
    }

    #[test]
    fn test_request_limits() {
        //WARNING: this test should never actually make any network connections as they are doomed to fail

        // the limit is just 2K, which is not sufficient for 4 BPs
        assert_fasta_within_limits("CGAT", Some(2_000), true, None);

        // the limit is 200KB, which is sufficient for 4 BPs
        // this is below the threshold of our min scanning size, so it will always return "Granted"
        assert_fasta_within_limits("CGAT", Some(200_000), false, None);

        // the limit is 100KB, which is not sufficient for 50 BPs
        assert_fasta_within_limits(
            "AAAAAAAAAA CCCCCCCCCC GGGGGGGGGG TTTTTTTTTT AAAAAAAAAA",
            Some(100_000),
            true,
            None,
        );
    }

    #[test]
    fn test_request_limits_limits_are_correct() {
        //WARNING: this test should never actually make any network connections as they are doomed to fail

        // the limit is 500KB, which is not sufficient for 50 BPs, only 48 BPs fit
        assert_fasta_within_limits(
            "AAAAAAAAAA CCCCCCCCCC GGGGGGGGGG TTTTTTTTTT AAAAAAAAAA",
            Some(100_000),
            true,
            Some(48),
        );

        // 1M+1 BPs is too big for system limits
        // since we dont set any memory limit the total limit is the system limit
        assert_fasta_within_limits(
            (0..1_000_001).map(|_| "A").collect::<String>().as_str(),
            None,
            true,
            Some(1_000_000),
        );

        // the request is larger than both system limit and memory limit
        // make sure we report the correct max
        assert_fasta_within_limits(
            (0..200_001).map(|_| "A").collect::<String>().as_str(),
            Some(100_000),
            true,
            Some(48),
        );
    }

    fn acquire_system_resources<'a>(
        config: &'a LimitConfiguration,
        fasta: &'a str,
    ) -> Result<RAIIAtomic<'a>, CheckFastaError> {
        let parser = FastaParser::<DnaSequence<Nucleotide>>::new(
            FastaParseSettings::new()
                .concatenate_headers(true)
                .allow_preceding_comment(false),
        );

        let records = parser.parse_str(fasta).unwrap().records;

        check_system_limits(config, &records)
    }

    #[test]
    fn check_system_limits_tests() {
        let counter = CurrentSystemLoadTracker {
            current_base_pair_counter: Default::default(),
        };

        let config = LimitConfiguration {
            memory_limit: Some(100 * 1024 * 2),
            max_request_bp: 1_000_000,
            limits: &counter,
        };

        {
            let _tracker = acquire_system_resources(
                &config,
                "AAAAAAAAAA CCCCCCCCCC GGGGGGGGGG TTTTTTTTTT AAAAAAAAAA",
            )
            .unwrap();

            let current_load = counter.current_base_pair_counter.load(Ordering::Relaxed);
            assert_eq!(current_load, 50);

            let tracker2 = acquire_system_resources(
                &config,
                "AAAAAAAAAA CCCCCCCCCC GGGGGGGGGG TTTTTTTTTT AAAAAAAAAA",
            )
            .unwrap();

            let current_load = counter.current_base_pair_counter.load(Ordering::Relaxed);
            assert_eq!(current_load, 100);

            drop(tracker2);

            let current_load = counter.current_base_pair_counter.load(Ordering::Relaxed);
            assert_eq!(current_load, 50);
        }

        let current_load = counter.current_base_pair_counter.load(Ordering::Relaxed);
        assert_eq!(current_load, 0);

        {
            let _tracker = acquire_system_resources(
                &config,
                "AAAAAAAAAA CCCCCCCCCC GGGGGGGGGG TTTTTTTTTT AAAAAAAAAA",
            )
            .unwrap();

            let current_load = counter.current_base_pair_counter.load(Ordering::Relaxed);
            assert_eq!(current_load, 50);

            let result = acquire_system_resources(
                &config,
                "AAAAAAAAAA CCCCCCCCCC GGGGGGGGGG TTTTTTTTTT AAAAAAAAAA \
                AAAAAAAAAA AAAAAAAAAA AAAAAAAAAA AAAAAAAAAA",
            );

            assert!(matches!(
                result,
                Err(CheckFastaError::TemporaryMemoryLimitsReached(90, 100))
            ));

            let current_load = counter.current_base_pair_counter.load(Ordering::Relaxed);
            assert_eq!(current_load, 50);
        }
    }
}
