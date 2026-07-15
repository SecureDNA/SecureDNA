// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod log;
mod output;

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, crate_version};
use csv::Writer;
use itertools::Itertools;
use rayon::prelude::*;
use serde::Serialize;
use shared_types::hash::{HashSpec, HashType, HashTypeDescriptor};
use time::format_description::well_known::Iso8601;
use tracing::{info, warn};

use doprf::prf::{KeyShare, Query};
use doprf_client::windows::Windows;
use hdb::consolidate_windows::HashId;
use hdb::response::HdbOrganism;
use hdb::shims::genhdb::open_file_maybe_gz;
use hdb::{ConsolidatedHazardResult, DebugSeqHdbResponse};
use hdb::{Database, HazardLookupTable, entry_to_response};
use quickdna::{
    BaseSequence, DnaSequence, DnaSequenceAmbiguous, FastaParseSettings, FastaParser, FastaRecord,
    NucleotideAmbiguous, TranslationTable,
};
use shared_types::synthesis_permission::{Region, SynthesisPermission};

use crate::log::{init_log, log_level_from_count};
use crate::output::DebugOutputSink;

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    run(&opts)
}

#[derive(Debug, Parser)]
#[clap(
    name = "awesome_hazard_analyzer",
    about = "Runs a collection of hazards against the local HDB",
    version = crate_version!()
)]
pub struct Opts {
    #[clap(short, global = true, action = clap::ArgAction::Count, help = "default INFO; v for DEBUG")]
    verbosity_level: u8,

    #[clap(long, help = "Hazardous DNA FASTA file or directory")]
    pub hazard_path: PathBuf,

    #[clap(long, help = "HDB directory")]
    pub hdb_dir: PathBuf,

    #[command(flatten)]
    pub secret_key_opts: SecretKeyOpts,

    #[clap(
        long,
        required = false,
        help = "Write debug files",
        num_args(0..=1),
        default_missing_value = "tarred",
    )]
    pub debug: Option<DebugOutputSinkKind>,

    #[clap(long, required = false, help = "Write CSV summary")]
    pub summary: bool,

    #[clap(long, required = false, help = "Do not generate 42mer DNA windows")]
    pub no_dna: bool,

    #[clap(
        long,
        required = false,
        help = "Do not generate 30mer DNA windows (runts)"
    )]
    pub no_runts: bool,

    #[clap(long, required = false, help = "Do not generate AA windows")]
    pub no_aa: bool,

    #[clap(long, default_value_t = NonZeroUsize::MIN, help = "Max expansions per window")]
    pub expansions_limit: NonZeroUsize,

    #[clap(
        long,
        required = false,
        help = "Output unconsolidated hits",
        num_args(0..=1),
        default_missing_value = "tarred",
    )]
    pub unconsolidated: Option<DebugOutputSinkKind>,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct SecretKeyOpts {
    #[clap(
        long,
        env = "SECUREDNA_AHA_SECRET_KEY",
        hide_env_values = true,
        help = "Secret key"
    )]
    pub secret_key: Option<KeyShare>,

    #[clap(long, help = "Path to load secret key")]
    pub secret_key_path: Option<PathBuf>,
}

impl SecretKeyOpts {
    fn read(&self) -> std::io::Result<KeyShare> {
        match (self.secret_key, &self.secret_key_path) {
            (Some(secret_key), None) => Ok(secret_key),
            (None, Some(secret_key_path)) => {
                let secret_key = fs::read_to_string(secret_key_path)?;
                secret_key
                    .trim()
                    .parse()
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
            }
            _ => unreachable!("clap should prevent this"),
        }
    }
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum DebugOutputSinkKind {
    Directory,
    Tarred,
}

impl DebugOutputSinkKind {
    fn new_output_sink(&self, path: &str) -> std::io::Result<DebugOutputSink> {
        match self {
            Self::Directory => DebugOutputSink::new_directory(path),
            Self::Tarred => DebugOutputSink::new_tarred(path),
        }
    }
}

pub struct AhaCheckerConfiguration<'a> {
    pub debug_output_sinks: Option<&'a DebugOutputSinks>,
    pub summary: bool,
    pub generate_dna_windows: bool,
    pub generate_runt_windows: bool,
    pub generate_aa_windows: bool,
    pub max_expansions_per_window: NonZeroUsize,
    pub unconsolidated_output_sink: Option<&'a DebugOutputSink>,
    pub max_filename_len: usize,
}

impl Default for AhaCheckerConfiguration<'_> {
    fn default() -> Self {
        AhaCheckerConfiguration {
            debug_output_sinks: None,
            summary: true,
            generate_dna_windows: true,
            generate_runt_windows: true,
            generate_aa_windows: true,
            max_expansions_per_window: NonZeroUsize::MIN,
            unconsolidated_output_sink: None,
            max_filename_len: usize::MAX,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SummaryLine {
    synthesis_permission: SummaryPermissions,
    true_hits: u32,
    true_dna_hits: u32,
    true_aa_hits: u32,
    rs_hits: u32,
    rs_dna_hits: u32,
    rs_aa_hits: u32,
    true_hits_percentage: f32,
    true_dna_hits_percentage: f32,
    true_aa_hits_percentage: f32,
    rs_hits_percentage: f32,
    rs_dna_hits_percentage: f32,
    rs_aa_hits_percentage: f32,
    red_name: String,
    true_likely_organisms: String,
    true_likely_ans: String,
    rs_likely_organisms: String,
    rs_likely_ans: String,
    // sorted (by enum variant) and deduplicated list of all tags from
    // full list of organisms hit (not just most_likely_organism) used
    // for determining synthesis permission.
    tags_for_permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryPermissions {
    all_region: SynthesisPermission,
    us: SynthesisPermission,
    prc: SynthesisPermission,
    eu: SynthesisPermission,
}

impl SummaryPermissions {
    pub fn header() -> [&'static str; 4] {
        [
            "SDNA PERMISSION (ALL)",
            "SDNA PERMISSION (US)",
            "SDNA PERMISSION (PRC)",
            "SDNA PERMISSION (EU)",
        ]
    }

    pub fn values(&self) -> [&'static str; 4] {
        [
            self.all_region.into(),
            self.us.into(),
            self.prc.into(),
            self.eu.into(),
        ]
    }
}

impl SummaryLine {
    pub fn write_header<W: Write>(wtr: &mut Writer<W>) -> anyhow::Result<()> {
        let perm_header = SummaryPermissions::header();
        wtr.write_record(perm_header.into_iter().chain([
            "TRUE HITS",
            "TRUE DNA HITS",
            "TRUE AA HITS",
            "RS HITS",
            "RS DNA HITS",
            "RS AA HITS",
            "TRUE HITS %",
            "TRUE DNA HITS %",
            "TRUE AA HITS %",
            "RS HITS %",
            "RS DNA HITS %",
            "RS AA HITS %",
            "RED NAME",
            "TAGS FOR PERMISSIONS",
            "TRUE LIKELY ORGANISMS",
            "TRUE LIKELY ANS",
            "RS LIKELY ORGANISMS",
            "RS LIKELY ANS",
        ]))
        .context("writing header")
    }

    pub fn write<W: Write>(&self, wtr: &mut Writer<W>) -> anyhow::Result<()> {
        let perm_values = self.synthesis_permission.values();
        wtr.write_record(perm_values.into_iter().chain([
            self.true_hits.to_string().as_str(),
            self.true_dna_hits.to_string().as_str(),
            self.true_aa_hits.to_string().as_str(),
            self.rs_hits.to_string().as_str(),
            self.rs_dna_hits.to_string().as_str(),
            self.rs_aa_hits.to_string().as_str(),
            &format!("{:.2}", self.true_hits_percentage),
            &format!("{:.2}", self.true_dna_hits_percentage),
            &format!("{:.2}", self.true_aa_hits_percentage),
            &format!("{:.2}", self.rs_hits_percentage),
            &format!("{:.2}", self.rs_dna_hits_percentage),
            &format!("{:.2}", self.rs_aa_hits_percentage),
            self.red_name.as_str(),
            self.tags_for_permissions.as_str(),
            self.true_likely_organisms.as_str(),
            self.true_likely_ans.as_str(),
            self.rs_likely_organisms.as_str(),
            self.rs_likely_ans.as_str(),
        ]))
        .with_context(|| format!("writing record: {}", self.red_name))
    }

    /// Takes `&[DebugSeqHdbResponse]`, the debug version of the consolidated hit regions,
    /// which treats each hit as a separate hit region.
    fn new_with_responses(
        synthesis_permission: SummaryPermissions,
        red_name: String,
        doprf_hit_results: &[DebugSeqHdbResponse],
        total_dna_windows: usize,
        total_aa_windows: usize,
    ) -> Self {
        let mut true_hits = 0;
        let mut true_dna_hits = 0;
        let mut true_aa_hits = 0;

        let mut rs_hits = 0;
        let mut rs_dna_hits = 0;
        let mut rs_aa_hits = 0;

        let mut true_likely_organisms = HashSet::new();
        let mut true_likely_ans = HashSet::new();
        let mut rs_likely_organisms = HashSet::new();
        let mut rs_likely_ans = HashSet::new();

        let mut tags_for_permissions = HashSet::new();

        for dhr in doprf_hit_results {
            let response = &dhr.hdb_response;
            if response.reverse_screened {
                rs_hits += 1;
                rs_dna_hits += u32::from(response.provenance.is_dna());
                rs_aa_hits += u32::from(!response.provenance.is_dna());
                rs_likely_organisms.insert(&response.most_likely_organism.name);
                rs_likely_ans.extend(&response.most_likely_organism.ans);
            } else {
                true_hits += 1;
                true_dna_hits += u32::from(response.provenance.is_dna());
                true_aa_hits += u32::from(!response.provenance.is_dna());
                true_likely_organisms.insert(&response.most_likely_organism.name);
                true_likely_ans.extend(&response.most_likely_organism.ans);
                for o in &response.organisms {
                    for tag in &o.tags {
                        tags_for_permissions.insert(format!("{:?}", &tag));
                    }
                }
            }
        }

        fn joined_sorted(h: HashSet<impl std::fmt::Display + Ord>) -> String {
            let mut v = Vec::from_iter(h);
            v.sort_unstable();
            v.iter().join(";")
        }

        let total_windows = total_dna_windows + total_aa_windows;
        let pct = |n: u32, d: usize| {
            if d == 0 {
                0.0
            } else {
                (n as f32 / d as f32) * 100.0
            }
        };
        let true_hits_percentage = pct(true_hits, total_windows);
        let true_dna_hits_percentage = pct(true_dna_hits, total_dna_windows);
        let true_aa_hits_percentage = pct(true_aa_hits, total_aa_windows);
        let rs_hits_percentage = pct(rs_hits, total_windows);
        let rs_dna_hits_percentage = pct(rs_dna_hits, total_dna_windows);
        let rs_aa_hits_percentage = pct(rs_aa_hits, total_aa_windows);

        Self {
            synthesis_permission,
            true_hits,
            true_dna_hits,
            true_aa_hits,
            rs_hits,
            rs_dna_hits,
            rs_aa_hits,
            true_hits_percentage,
            true_dna_hits_percentage,
            true_aa_hits_percentage,
            rs_hits_percentage,
            rs_dna_hits_percentage,
            rs_aa_hits_percentage,
            red_name,
            true_likely_organisms: joined_sorted(true_likely_organisms),
            true_likely_ans: joined_sorted(true_likely_ans),
            rs_likely_organisms: joined_sorted(rs_likely_organisms),
            rs_likely_ans: joined_sorted(rs_likely_ans),
            tags_for_permissions: joined_sorted(tags_for_permissions),
        }
    }
}

/// Output of `ConsolidatedHazardResult`, but with
/// - hdb response un-nested
/// - field names aligned with synthclient
///
/// so that output looks more like api response, but without losing "debug"-type info
#[derive(Debug, Serialize)]
struct DebugOutput {
    hit_regions: Vec<HitRegion>,
    most_likely_organism: HdbOrganism,
    organisms: Vec<HdbOrganism>,
    // turned into `is_wild_type` and `sequence_type in API`
    provenance: hdb::Provenance,
    // not in API
    an_likelihood: f32,
    // not in API
    reverse_screened: bool,
    window_gap: usize,
    sequence_length: usize,
}

/// Same as hdb::HitRegion, except with a `seq` field
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HitRegion {
    pub seq: String,
    #[serde(flatten)]
    pub hit_region: hdb::HitRegion,
}

// To help disambiguate the with_rs and no_rs dirs, as Rust doesn't have named args and it's easy
// to get the order wrong.
pub struct DebugOutputSinks {
    with_rs: DebugOutputSink,
    no_rs: DebugOutputSink,
    overlap: DebugOutputSink,
}

impl DebugOutputSinks {
    fn new(kind: DebugOutputSinkKind, path: impl AsRef<str>) -> anyhow::Result<Self> {
        // these are the directories the debug .gz files are stored in. One for with rs, one
        // with no rs, one for overlaps
        let path = path.as_ref();
        let with_rs = format!("{path}.with-rs");
        let no_rs = format!("{path}.no-rs");
        let overlap = format!("{path}.overlap");
        Ok(DebugOutputSinks {
            with_rs: (kind.new_output_sink(&with_rs))
                .with_context(|| format!("creating debug output {with_rs}"))?,
            no_rs: (kind.new_output_sink(&no_rs))
                .with_context(|| format!("creating debug output {no_rs}"))?,
            overlap: (kind.new_output_sink(&overlap))
                .with_context(|| format!("creating debug output {overlap}"))?,
        })
    }

    fn close(self) -> std::io::Result<()> {
        self.with_rs.close()?;
        self.no_rs.close()?;
        self.overlap.close()?;
        Ok(())
    }
}

const DEBUG_SUFFIX: &str = ".debug";

/// Check a single FASTA record.
/// Returns Some(header), if the record is NOT a hazard
/// Returns None, if the record is a hazard
/// If config.summary is specified, will return a parsed summary in the second return object
fn check_one_record(
    database: &Database,
    hlt: &HazardLookupTable,
    secret_key: &KeyShare,
    record: FastaRecord<DnaSequence<NucleotideAmbiguous>>,
    config: AhaCheckerConfiguration,
) -> anyhow::Result<(Option<String>, Option<SummaryLine>)> {
    if record.contents.is_empty() {
        warn!("no contents received");
        return Ok((None, None));
    }

    let mut htdv = vec![];
    if config.generate_dna_windows {
        htdv.push(HashTypeDescriptor::dna_normal_cech());
    }
    if config.generate_runt_windows {
        htdv.push(HashTypeDescriptor::dna_runt_cech());
    }
    let aa_fw_htd = htdv.len(); // if !config.generate_aa_windows, this won't match any htd_index
    let aa_rc_htd = aa_fw_htd + 1; // ditto
    if config.generate_aa_windows {
        htdv.push(HashTypeDescriptor::aa_fw());
        htdv.push(HashTypeDescriptor::aa_rc());
    }

    let hash_spec = HashSpec {
        max_expansions_per_window: config.max_expansions_per_window,
        htdv,
    };

    let windows_object =
        Windows::from_dna(record.contents.as_slice(), &hash_spec).expect("failed to build windows");
    let mut last_record = None;
    let windows: Vec<_> = windows_object
        .map(|(tag, window)| {
            let hash_id = HashId::new(tag, last_record);
            last_record = Some(hash_id.record);
            (hash_id, window)
        })
        .collect();

    if windows.is_empty() {
        warn!("No windows were generated for {}", record.header);
        return Ok((Some(record.header), None));
    }

    // query local HDB (and count DNA vs AA windows)
    let dna_count = AtomicUsize::new(0);
    let aa_count = AtomicUsize::new(0);
    let hdb_entries = windows
        .par_iter()
        .filter_map(|(hash_id, window)| {
            if (hash_id.hash_type_index as usize) < hash_spec.htdv.len() {
                match hash_spec.htdv[hash_id.hash_type_index as usize].hash_type {
                    HashType::Dna => dna_count.fetch_add(1, Ordering::Relaxed),
                    HashType::Aa | HashType::Aa0 | HashType::Aa1 | HashType::Aa2 => {
                        aa_count.fetch_add(1, Ordering::Relaxed)
                    }
                };
            }
            let hash = secret_key.apply(Query::hash_from_string(window));
            let entry = database
                .query(&hash.into())
                .context("failed to lookup entry")
                .transpose()?; // propagate None
            Some(entry.map(|entry| (*hash_id, entry)))
        })
        .collect::<Result<Vec<(HashId, hdb::Entry)>, _>>()
        .context("failed to query hdb")?;
    let dna_count = dna_count.load(Ordering::Relaxed);
    let aa_count = aa_count.load(Ordering::Relaxed);

    // build hdb responses for consolidated/debug output (with region=None)
    let hdb_responses = hdb_entries
        .iter()
        .map(|(query_idx, entry)| -> Result<_> {
            let response = entry_to_response(*entry, Region::All, &Default::default(), hlt)
                .context("failed to convert entry to response")?;
            Ok((*query_idx, response))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // make consolidated responses (from region=None hdb responses)
    // Note that from AHA we always pass debug=true to hdb::consolidate_windows
    // This is not to be confused with the config.debug AHA flag whose value may change
    let consolidation =
        hdb::consolidate_windows::consolidate_windows(hdb_responses.into_iter(), &hash_spec, true)?;

    // make debug responses (from region=None hdb responses)
    // NOTE: hdb response debug output, where each hit is treated as a hit region (unconsolidated)
    // is used for creating the summary line, and doing general counts. It is _not_ used for debug
    // output of AHA.

    // As AHA always recieves debug info from hdb::consolidate_windows, we can unwrap here
    let consolidation_debug = consolidation.debug.unwrap();
    let unconsolidated_responses = consolidation_debug.unconsolidated_responses;
    let num_hits_no_rs = unconsolidated_responses
        .iter()
        .filter(|doprf_hazard_result| !doprf_hazard_result.hdb_response.reverse_screened)
        .count();

    info!(
        "Found {} hazard matches for {}",
        num_hits_no_rs, record.header
    );

    let file_id = file_id(&record.header, config.max_filename_len);

    // Write all unconsolidated hits
    if let Some(output_sink) = config.unconsolidated_output_sink
        && let Err(e) = output_sink.output(&file_id, unconsolidated_responses.iter())
    {
        warn!(
            "err on write unconsolidated hits file for {}: {:#}",
            record.header, e
        );
    }

    // We write all consolidated hits, even if the hits are completely rs'd.
    // However, we will not write a particular file if that file would be empty.
    if let Some(debug_output_sinks) = config.debug_output_sinks {
        let filename = format!("{file_id}{DEBUG_SUFFIX}");

        let sequence_length = record.contents.len();
        let sequence = record.contents.as_slice();
        let to_debug_output = |r: &ConsolidatedHazardResult| DebugOutput {
            hit_regions: hit_regions_with_seq(&r.hit_regions, sequence, aa_fw_htd, aa_rc_htd),
            most_likely_organism: r.hdb_response.most_likely_organism.clone(),
            organisms: r.hdb_response.organisms.clone(),
            provenance: r.hdb_response.provenance,
            an_likelihood: r.hdb_response.an_likelihood,
            reverse_screened: r.hdb_response.reverse_screened,
            window_gap: r.hdb_response.window_gap,
            sequence_length,
        };

        if let Err(e) = debug_output_sinks.with_rs.output(
            &filename,
            consolidation
                .results
                .iter()
                .filter(|r| is_rs(r))
                .map(to_debug_output),
        ) {
            warn!("err on write debug file for {}: {:#}", record.header, e);
        }
        if let Err(e) = debug_output_sinks.no_rs.output(
            &filename,
            consolidation
                .results
                .iter()
                .filter(|r| !is_rs(r))
                .map(to_debug_output),
        ) {
            warn!("err on write debug file for {}: {:#}", record.header, e);
        }
        if let Err(e) = debug_output_sinks.overlap.output(
            &filename,
            consolidation_debug
                .removed_overlaps
                .iter()
                .map(to_debug_output),
        ) {
            warn!("err on write debug file for {}: {:#}", record.header, e);
        }
    }

    // Calculate synthesis_permission for each region
    let entries = || hdb_entries.iter().map(|(_, e)| *e);
    let permissions = SummaryPermissions {
        all_region: calculate_synthesis_permission(entries(), Region::All, hlt)?,
        us: calculate_synthesis_permission(entries(), Region::Us, hlt)?,
        prc: calculate_synthesis_permission(entries(), Region::Prc, hlt)?,
        eu: calculate_synthesis_permission(entries(), Region::Eu, hlt)?,
    };

    let csv_summary: Option<SummaryLine> = config.summary.then(|| {
        SummaryLine::new_with_responses(
            permissions,
            record.header.clone(),
            &unconsolidated_responses,
            dna_count,
            aa_count,
        )
    });

    // TODO: The header is returned only so that it can be put in a log when num_hazards == 0
    // It's a bit confusing w/out more explanation why, so think about refactor.
    if num_hits_no_rs == 0 {
        Ok((Some(record.header), csv_summary))
    } else {
        Ok((None, csv_summary))
    }
}

fn file_id(header: &str, max_filename_len: usize) -> String {
    // Only replace `/`, which is not a valid filename char. Otherwise preserve header to make
    // search easier
    let mut file_id = header.replace('/', "_");

    // I'd like --unconsolidated and --debug output to have filenames that are consistent with
    // one another, so let's choose a max len that works if there's a .debug suffix.
    let max_filename_len = max_filename_len.saturating_sub(DEBUG_SUFFIX.len());

    if file_id.len() > max_filename_len {
        let ellipsis = "|{...}"; // In practice |{ doesn't show up in actual headers
        let target_len = max_filename_len.saturating_sub(ellipsis.len());
        // This is ignorant of graphemes, but realistically file_id is probably ASCII so...
        if let Some(i) = (0..target_len + 1).rposition(|i| file_id.is_char_boundary(i)) {
            file_id.replace_range(i.., ellipsis);
        }
    };

    file_id
}

/// Calculate merged synthesis_permission for the given region from the HDB entries
fn calculate_synthesis_permission(
    hdb_entries: impl Iterator<Item = hdb::Entry>,
    region: Region,
    hlt: &HazardLookupTable,
) -> Result<SynthesisPermission> {
    let mut permission = SynthesisPermission::Granted;
    for entry in hdb_entries {
        let response = entry_to_response(entry, region, &Default::default(), hlt)?;
        permission = SynthesisPermission::merge([permission, response.synthesis_permission]);
    }
    Ok(permission)
}

fn is_rs(r: &ConsolidatedHazardResult) -> bool {
    r.hdb_response.reverse_screened
}

fn hit_regions_with_seq(
    hit_regions: &[hdb::HitRegion],
    seq: &[NucleotideAmbiguous],
    aa_fw_htd: usize,
    aa_rc_htd: usize,
) -> Vec<HitRegion> {
    hit_regions
        .iter()
        .map(|hr| {
            let seq = DnaSequenceAmbiguous::new(seq[hr.seq_range_start..hr.seq_range_end].to_vec());
            let seq = if hr.htd_index == aa_fw_htd {
                seq.translate(TranslationTable::Ncbi1).to_string()
            } else if hr.htd_index == aa_rc_htd {
                seq.reverse_complement()
                    .translate(TranslationTable::Ncbi1)
                    .to_string()
            } else {
                seq.to_string()
            };
            HitRegion {
                seq,
                hit_region: hr.clone(),
            }
        })
        .collect()
}

fn run(opts: &Opts) -> anyhow::Result<()> {
    // time offset should be initialized asap to avoid issues with localtime_r, see docs for
    // `init_log`.
    let time_offset = time::UtcOffset::current_local_offset()?;

    let log_level = log_level_from_count(opts.verbosity_level)?;
    init_log(log_level, time_offset)?;

    // used for dir and file names
    let start_time_str = time::OffsetDateTime::now_local()
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
        .format(&Iso8601::DEFAULT)
        .unwrap();

    info!("Starting up...");
    info!("Using DB at path: {:?}", opts.hdb_dir);
    let build_info = fs::read_to_string(opts.hdb_dir.join("BUILD_INFO.json"))?;
    let build_info = build_info.replace("\n", "");
    info!("Using DB with BUILD_INFO.json: {}", build_info);

    let database = Database::open(opts.hdb_dir.clone()).expect("failed to open database");
    let hlt = HazardLookupTable::read(&opts.hdb_dir).expect("failed to open HLT");

    let parser = FastaParser::<DnaSequence<NucleotideAmbiguous>>::new(
        FastaParseSettings::new()
            .concatenate_headers(true)
            .allow_preceding_comment(false),
    );

    let max_filename_len =
        DebugOutputSink::max_filename_len(".").context("couldn't query max filename length")?;

    let unconsolidated_output_sink = match &opts.unconsolidated {
        Some(kind) => {
            let dir = format!("unconsolidated-hits-{start_time_str}");
            Some(kind.new_output_sink(&dir)?)
        }
        None => None,
    };

    let debug_output_sinks = match &opts.debug {
        Some(kind) => {
            let debug_path = format!("./debug-output-{start_time_str}");
            Some(DebugOutputSinks::new(*kind, debug_path)?)
        }
        None => None,
    };

    if !opts.hazard_path.exists() {
        return Err(anyhow!("Hazard path does not exist"));
    }

    let mut paths: Vec<PathBuf> = vec![];

    if opts.hazard_path.is_dir() {
        paths.extend(
            fs::read_dir(opts.hazard_path.clone())?
                .flatten()
                .map(|dir| dir.path()),
        );
        paths.sort();
    } else {
        paths = vec![opts.hazard_path.clone()];
    }

    let mut summary_file = None;

    if opts.summary {
        let filename = format!("summary-{}.csv", start_time_str);
        let mut wtr = Writer::from_path(filename)?;
        SummaryLine::write_header(&mut wtr)?;
        summary_file = Some(wtr);
    }

    if opts.no_aa {
        info!("Skipping generation of AA windows");
    }

    if opts.no_dna {
        info!("Skipping generation of DNA windows");
    }

    let secret_key = opts.secret_key_opts.read()?;

    for hazard_file in paths {
        let now = Instant::now();

        info!("Analyzing hazard {:?}...", hazard_file.as_path());

        let file = open_file_maybe_gz(hazard_file.as_path())?;
        let fastas = parser.parse(file)?;
        let csv_lines = fastas
            .records
            .into_par_iter()
            .map(|r| {
                check_one_record(
                    &database,
                    &hlt,
                    &secret_key,
                    r,
                    AhaCheckerConfiguration {
                        debug_output_sinks: debug_output_sinks.as_ref(),
                        summary: opts.summary,
                        generate_dna_windows: !opts.no_dna,
                        generate_runt_windows: !opts.no_runts,
                        generate_aa_windows: !opts.no_aa,
                        max_expansions_per_window: opts.expansions_limit,
                        unconsolidated_output_sink: unconsolidated_output_sink.as_ref(),
                        max_filename_len,
                    },
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|(header, csv)| {
                if let Some(non_hazard) = header {
                    warn!("No windows matched for {}", non_hazard);
                }
                csv
            });

        if let Some(ref mut wtr) = summary_file {
            for line in csv_lines {
                line.write(wtr)?;
            }
        }

        info!(
            "Done with {:?}! Took: {:.2?}",
            hazard_file.as_path(),
            now.elapsed()
        );
    }

    if let Some(debug_output_sinks) = debug_output_sinks {
        debug_output_sinks.close()?;
    }

    Ok(())
}

#[cfg(test)]
#[cfg(feature = "run_system_tests")]
mod tests {
    use super::*;
    use doprf::prf::KeyShare;
    use hdb::{Database, HazardLookupTable};
    use quickdna::{
        DnaSequence, FastaParseSettings, FastaParser, FastaRecord, NucleotideAmbiguous,
    };
    use std::str::FromStr;

    fn prepare() -> (Database, HazardLookupTable, KeyShare) {
        let secret_key = std::env::var("SECUREDNA_AHA_SECRET_KEY").expect(
            "Set the environment variable SECUREDNA_AHA_SECRET_KEY to run AHA system tests.",
        );
        (
            Database::open("../../test/data/hdb/")
                .expect("failed to open database (try running `git lfs pull`)"),
            HazardLookupTable::read("../../test/data/hdb/").expect("failed to open HLT"),
            KeyShare::from_str(&secret_key).unwrap(),
        )
    }

    fn parse_one(fasta: &str) -> FastaRecord<DnaSequence<NucleotideAmbiguous>> {
        let parser = FastaParser::<DnaSequence<NucleotideAmbiguous>>::new(
            FastaParseSettings::new()
                .concatenate_headers(true)
                .allow_preceding_comment(false),
        );

        let r = parser.parse_str(fasta).unwrap();
        assert_eq!(r.records.len(), 1);
        r.into_iter().next().unwrap()
    }

    #[test]
    fn test_known_hazard() {
        let (database, hlt, ks) = prepare();
        let r =
            parse_one(">Influenza\nCTTCGCGGGATGAGTGTTTTGCCATCTAATAAGTCCAACATTAATTACGGTGCATCAGGC");

        let (ele, _) = check_one_record(
            &database,
            &hlt,
            &ks,
            r,
            AhaCheckerConfiguration {
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(ele, None);
    }

    #[test]
    fn test_known_non_hazard() {
        let (database, hlt, ks) = prepare();
        let r = parse_one(
            ">Not a hazard
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
GGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        );

        let (ele, _) = check_one_record(
            &database,
            &hlt,
            &ks,
            r,
            AhaCheckerConfiguration {
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(ele, Some(String::from("Not a hazard")));
    }

    #[test]
    fn test_short_sequence() {
        let (database, hlt, ks) = prepare();
        let r = parse_one(
            ">Short sequence
ACGT",
        );

        let (ele, _) = check_one_record(
            &database,
            &hlt,
            &ks,
            r,
            AhaCheckerConfiguration {
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(ele, Some(String::from("Short sequence")));
    }

    #[test]
    fn test_no_summary() {
        let (database, hlt, ks) = prepare();
        let r = parse_one(
            ">Nonmatching
ACGTAGCTCGAAGCTAGAGATCGATAGCGATAAATCGATAGCTAATGATAGGGCGCGATATATAGCATCG",
        );

        assert_eq!(
            check_one_record(
                &database,
                &hlt,
                &ks,
                r,
                AhaCheckerConfiguration {
                    summary: false,
                    ..Default::default()
                },
            )
            .unwrap(),
            (Some("Nonmatching".into()), None)
        );
    }

    #[test]
    fn test_with_non_matching_summary() {
        let (database, hlt, ks) = prepare();
        let r = parse_one(
            ">Nonmatching
ACGTAGCTCGAAGCTAGAGATCGATAGCGATAAATCGATAGCTAATGATAGGGCGCGATATATAGCATCG",
        );

        assert_eq!(
            check_one_record(&database, &hlt, &ks, r, AhaCheckerConfiguration::default()).unwrap(),
            (
                Some("Nonmatching".into()),
                Some(SummaryLine {
                    synthesis_permission: SummaryPermissions {
                        all_region: SynthesisPermission::Granted,
                        us: SynthesisPermission::Granted,
                        prc: SynthesisPermission::Granted,
                        eu: SynthesisPermission::Granted,
                    },
                    red_name: "Nonmatching".into(),
                    true_hits: 0,
                    true_dna_hits: 0,
                    true_aa_hits: 0,
                    rs_hits: 0,
                    rs_dna_hits: 0,
                    rs_aa_hits: 0,
                    true_hits_percentage: 0.0,
                    true_dna_hits_percentage: 0.0,
                    true_aa_hits_percentage: 0.0,
                    rs_hits_percentage: 0.0,
                    rs_dna_hits_percentage: 0.0,
                    rs_aa_hits_percentage: 0.0,
                    true_likely_organisms: "".into(),
                    true_likely_ans: "".into(),
                    rs_likely_organisms: "".into(),
                    rs_likely_ans: "".into(),
                    tags_for_permissions: "".into()
                })
            )
        );
    }

    #[test]
    fn test_with_matching_summary() {
        let (database, hlt, ks) = prepare();
        let r =
            parse_one(">Influenza\nCTTCGCGGGATGAGTGTTTTGCCATCTAATAAGTCCAACATTAATTACGGTGCATCAGGC");

        assert_eq!(
            check_one_record(
                &database,
                &hlt,
                &ks,
                r.clone(),
                AhaCheckerConfiguration::default(),
            )
            .unwrap(),
            (
                None,
                Some(SummaryLine {
                    synthesis_permission: SummaryPermissions {
                        all_region: SynthesisPermission::Denied,
                        us: SynthesisPermission::Granted,
                        prc: SynthesisPermission::Granted,
                        eu: SynthesisPermission::Denied,
                    },
                    red_name: "Influenza".into(),
                    true_hits: 51,
                    true_dna_hits: 50,
                    true_aa_hits: 1,
                    rs_hits: 0,
                    rs_dna_hits: 0,
                    rs_aa_hits: 0,
                    true_hits_percentage: 98.07692,
                    true_dna_hits_percentage: 100.0,
                    true_aa_hits_percentage: 50.0,
                    rs_hits_percentage: 0.0,
                    rs_dna_hits_percentage: 0.0,
                    rs_aa_hits_percentage: 0.0,
                    true_likely_organisms: "Minimal organism".into(),
                    true_likely_ans: "AN1000000.1".into(),
                    rs_likely_organisms: "".into(),
                    rs_likely_ans: "".into(),
                    tags_for_permissions: "EuropeanUnion".into()
                })
            )
        );

        // hogs only
        assert_eq!(
            check_one_record(
                &database,
                &hlt,
                &ks,
                r.clone(),
                AhaCheckerConfiguration {
                    generate_runt_windows: false,
                    generate_aa_windows: false,
                    ..Default::default()
                },
            )
            .unwrap(),
            (
                None,
                Some(SummaryLine {
                    synthesis_permission: SummaryPermissions {
                        all_region: SynthesisPermission::Denied,
                        us: SynthesisPermission::Granted,
                        prc: SynthesisPermission::Granted,
                        eu: SynthesisPermission::Denied,
                    },
                    red_name: "Influenza".into(),
                    true_hits: 19,
                    true_dna_hits: 19,
                    true_aa_hits: 0,
                    rs_hits: 0,
                    rs_dna_hits: 0,
                    rs_aa_hits: 0,
                    true_hits_percentage: 100.0,
                    true_dna_hits_percentage: 100.0,
                    true_aa_hits_percentage: 0.0,
                    rs_hits_percentage: 0.0,
                    rs_dna_hits_percentage: 0.0,
                    rs_aa_hits_percentage: 0.0,
                    true_likely_organisms: "Minimal organism".into(),
                    true_likely_ans: "AN1000000.1".into(),
                    rs_likely_organisms: "".into(),
                    rs_likely_ans: "".into(),
                    tags_for_permissions: "EuropeanUnion".into()
                })
            )
        );

        // TODO: Test only runts once the test HDB contains them?

        // aa only
        assert_eq!(
            check_one_record(
                &database,
                &hlt,
                &ks,
                r,
                AhaCheckerConfiguration {
                    generate_dna_windows: false,
                    generate_runt_windows: false,
                    ..Default::default()
                },
            )
            .unwrap(),
            (
                None,
                Some(SummaryLine {
                    synthesis_permission: SummaryPermissions {
                        all_region: SynthesisPermission::Denied,
                        us: SynthesisPermission::Granted,
                        prc: SynthesisPermission::Granted,
                        eu: SynthesisPermission::Denied,
                    },
                    red_name: "Influenza".into(),
                    true_hits: 1,
                    true_dna_hits: 0,
                    true_aa_hits: 1,
                    rs_hits: 0,
                    rs_dna_hits: 0,
                    rs_aa_hits: 0,
                    true_hits_percentage: 50.0,
                    true_dna_hits_percentage: 0.0,
                    true_aa_hits_percentage: 50.0,
                    rs_hits_percentage: 0.0,
                    rs_dna_hits_percentage: 0.0,
                    rs_aa_hits_percentage: 0.0,
                    true_likely_organisms: "Minimal organism".into(),
                    true_likely_ans: "AN1000000.1".into(),
                    rs_likely_organisms: "".into(),
                    rs_likely_ans: "".into(),
                    tags_for_permissions: "EuropeanUnion".into()
                })
            )
        );
    }

    #[test]
    fn test_csv_output() {
        let summary_line = SummaryLine {
            synthesis_permission: SummaryPermissions {
                all_region: SynthesisPermission::Denied,
                us: SynthesisPermission::Denied,
                prc: SynthesisPermission::Granted,
                eu: SynthesisPermission::Denied,
            },
            red_name: "red,name".into(),
            true_hits: 123,
            true_dna_hits: 4,
            true_aa_hits: 56,
            rs_hits: 78,
            rs_dna_hits: 9,
            rs_aa_hits: 0,
            true_hits_percentage: 100.0,
            true_dna_hits_percentage: 100.0,
            true_aa_hits_percentage: 100.0,
            rs_hits_percentage: 0.0,
            rs_dna_hits_percentage: 100.0,
            rs_aa_hits_percentage: 100.0,
            true_likely_organisms: "true likely;organisms".into(),
            true_likely_ans: "AN_12345".into(),
            rs_likely_organisms: "rs likely".into(),
            rs_likely_ans: "AN_56789".into(),
            tags_for_permissions: "EuropeanUnion".into(),
        };

        let csv = {
            let mut buffer = Vec::new();
            let mut wtr = csv::Writer::from_writer(&mut buffer);
            summary_line.write(&mut wtr).unwrap();
            drop(wtr);
            String::from_utf8(buffer).unwrap()
        };

        assert_eq!(
            csv,
            "denied,denied,granted,denied,123,4,56,78,9,0,100.00,100.00,100.00,0.00,100.00,100.00,\"red,name\",EuropeanUnion,true likely;organisms,AN_12345,rs likely,AN_56789\n",
        );
    }
}
