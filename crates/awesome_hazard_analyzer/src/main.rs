// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod log;

use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use clap::{crate_version, Parser};
use csv::Writer;
use flate2::write::GzEncoder;
use flate2::Compression;
use itertools::Itertools;
use rayon::prelude::*;
use serde::Serialize;
use shared_types::hash::{HashSpec, HashTypeDescriptor};
use time::format_description::well_known::Iso8601;
use tracing::{info, warn};

use crate::log::{init_log, log_level_from_count};
use doprf::prf::{KeyShare, Query};
use doprf_client::windows::Windows;
use hdb::consolidate_windows::HashId;
use hdb::response::HdbOrganism;
use hdb::shims::genhdb::open_file_maybe_gz;
use hdb::{entry_to_response, Database, HazardLookupTable};
use hdb::{ConsolidatedHazardResult, DebugSeqHdbResponse, Provenance};
use quickdna::{
    BaseSequence, DnaSequence, DnaSequenceAmbiguous, FastaParseSettings, FastaParser, FastaRecord,
    NucleotideAmbiguous, TranslationTable,
};
use shared_types::synthesis_permission::{Region, SynthesisPermission};

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

    #[clap(long, help = "Generator secret key")]
    pub secret_key: KeyShare,

    #[clap(long, required = false, help = "Write debug files")]
    pub debug: bool,

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
}

pub struct AhaCheckerConfiguration {
    pub debug: bool,
    pub summary: bool,
    pub generate_dna_windows: bool,
    pub generate_runt_windows: bool,
    pub generate_aa_windows: bool,
    pub max_expansions_per_window: NonZeroUsize,
}

impl Default for AhaCheckerConfiguration {
    fn default() -> Self {
        AhaCheckerConfiguration {
            debug: false,
            summary: true,
            generate_dna_windows: true,
            generate_runt_windows: true,
            generate_aa_windows: true,
            max_expansions_per_window: NonZeroUsize::MIN,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryLine {
    synthesis_permission: SummaryPermissions,
    true_hits: u32,
    true_dna_hits: u32,
    true_aa_hits: u32,
    rs_hits: u32,
    rs_dna_hits: u32,
    rs_aa_hits: u32,
    red_name: String,
    true_likely_organisms: String,
    true_likely_ans: String,
    rs_likely_organisms: String,
    rs_likely_ans: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryPermissions {
    no_region: SynthesisPermission,
    us: SynthesisPermission,
    prc: SynthesisPermission,
    eu: SynthesisPermission,
}

impl SummaryPermissions {
    pub fn header() -> [&'static str; 4] {
        [
            "SDNA PERMISSION",
            "SDNA PERMISSION (US)",
            "SDNA PERMISSION (PRC)",
            "SDNA PERMISSION (EU)",
        ]
    }

    pub fn values(&self) -> [&'static str; 4] {
        [
            self.no_region.into(),
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
            "RED NAME",
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
            self.red_name.as_str(),
            self.true_likely_organisms.as_str(),
            self.true_likely_ans.as_str(),
            self.rs_likely_organisms.as_str(),
            self.rs_likely_ans.as_str(),
        ]))
        .with_context(|| format!("writing record: {}", self.red_name))
    }

    /// Currently takes `&[DebugSeqHdbResponse]`, but once hit region consolidation moves to hdb,
    /// this will take a slice of HdbResponse again.
    ///
    /// It's expected that this will take in the debug version of the consolidated hit regions,
    /// which treats each hit as a separate hit region.
    fn new_with_responses(
        synthesis_permission: SummaryPermissions,
        red_name: String,
        doprf_hit_results: &[DebugSeqHdbResponse],
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
            }
        }

        fn joined_sorted(h: HashSet<&String>) -> String {
            let mut v = Vec::from_iter(h);
            v.sort_unstable();
            v.iter().join(";")
        }

        Self {
            synthesis_permission,
            true_hits,
            true_dna_hits,
            true_aa_hits,
            rs_hits,
            rs_dna_hits,
            rs_aa_hits,
            red_name,
            true_likely_organisms: joined_sorted(true_likely_organisms),
            true_likely_ans: joined_sorted(true_likely_ans),
            rs_likely_organisms: joined_sorted(rs_likely_organisms),
            rs_likely_ans: joined_sorted(rs_likely_ans),
        }
    }
}

/// Output of `ConsolidatedHazardResult`, but with
/// - hdb response un-nested
/// - field names aligned with synthclient
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
struct DebugDirs {
    with_rs: String,
    no_rs: String,
}

/// Check a single FASTA record.
/// Returns Some(header), if the record is NOT a hazard
/// Returns None, if the record is a hazard
/// If config.summary is specified, will return a parsed summary in the second return object
fn check_one_record(
    database: &Database,
    hlt: &HazardLookupTable,
    secret_key: &KeyShare,
    record: FastaRecord<DnaSequence<NucleotideAmbiguous>>,
    debug_dirs: Option<&DebugDirs>,
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

    // query local HDB
    let hdb_entries = windows
        .par_iter()
        .filter_map(|(hash_id, window)| {
            let hash = secret_key.apply(Query::hash_from_string(window));
            let entry = database
                .query(&hash.into())
                .context("failed to lookup entry")
                .transpose()?; // propagate None
            Some(entry.map(|entry| (*hash_id, entry)))
        })
        .collect::<Result<Vec<(HashId, hdb::Entry)>, _>>()
        .context("failed to query hdb")?;

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
    let consolidation =
        hdb::consolidate_windows::consolidate_windows(hdb_responses.into_iter(), &hash_spec, true)?;

    // make debug responses (from region=None hdb responses)
    // NOTE: hdb response debug output, where each hit is treated as a hit region (unconsolidated)
    // is used for creating the summary line, and doing general counts. It is _not_ used for debug
    // output of AHA.

    let consolidated_responses_debug = consolidation.debug_hdb_responses.unwrap();
    let num_hits_no_rs = consolidated_responses_debug
        .iter()
        .filter(|doprf_hazard_result| !doprf_hazard_result.hdb_response.reverse_screened)
        .count();

    info!(
        "Found {} hazard matches for {}",
        num_hits_no_rs, record.header
    );

    // Calculate synthesis_permission for each region
    let entries = || hdb_entries.iter().map(|(_, e)| *e);
    let permissions = SummaryPermissions {
        no_region: calculate_synthesis_permission(entries(), Region::All, hlt)?,
        us: calculate_synthesis_permission(entries(), Region::Us, hlt)?,
        prc: calculate_synthesis_permission(entries(), Region::Prc, hlt)?,
        eu: calculate_synthesis_permission(entries(), Region::Eu, hlt)?,
    };

    // We write all hits, even if the hits are completely rs'd.
    // However, we will not write a particular file if that file would be empty.
    if config.debug {
        let debug_dirs = debug_dirs.expect("bug: debug dirs not passed with config.debug = true");
        let debug_dir_with_rs = &debug_dirs.with_rs;
        let debug_dir_no_rs = &debug_dirs.no_rs;

        // Only replace `/`, which is not a valid filename char. Otherwise preserve header to make
        // search easier
        let file_id = record.header.replace('/', "_");
        let filename_with_rs = format!("./{debug_dir_with_rs}/{file_id}.debug.gz");
        let filename_no_rs = format!("./{debug_dir_no_rs}/{file_id}.debug.gz");

        if let Err(e) = write_debug(
            &filename_with_rs,
            record.contents.len(),
            consolidation.results.iter().filter(|r| is_rs(r)),
            record.contents.as_slice(),
        ) {
            warn!("err on write debug file for {}: {:#}", record.header, e);
        }
        if let Err(e) = write_debug(
            &filename_no_rs,
            record.contents.len(),
            consolidation.results.iter().filter(|r| !is_rs(r)),
            record.contents.as_slice(),
        ) {
            warn!("err on write debug file for {}: {:#}", record.header, e);
        }
    }

    let csv_summary: Option<SummaryLine> = config.summary.then(|| {
        SummaryLine::new_with_responses(
            permissions,
            record.header.clone(),
            &consolidated_responses_debug,
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

// Creates file, if needed, and then writes the debug output
// This helper fn makes it easier to write with-rs and no-rs separately, and
// avoid creating an unnecessary file
fn write_debug<'a>(
    filename: &str,
    sequence_length: usize,
    consolidated_responses: impl Iterator<Item = &'a ConsolidatedHazardResult> + Clone,
    seq: &[NucleotideAmbiguous],
) -> Result<()> {
    if consolidated_responses.clone().count() == 0 {
        // early return to avoid creating an empty file
        return Ok(());
    };

    let f = File::create(filename)?;
    let mut f = GzEncoder::new(BufWriter::new(f), Compression::default());
    for r in consolidated_responses {
        let output = DebugOutput {
            hit_regions: hit_regions_with_seq(&r.hit_regions, seq, r.hdb_response.provenance),
            most_likely_organism: r.hdb_response.most_likely_organism.clone(),
            organisms: r.hdb_response.organisms.clone(),
            provenance: r.hdb_response.provenance,
            an_likelihood: r.hdb_response.an_likelihood,
            reverse_screened: r.hdb_response.reverse_screened,
            window_gap: r.hdb_response.window_gap,
            sequence_length,
        };
        serde_json::to_writer(&mut f, &output)?;
        writeln!(&mut f)?;
    }
    f.finish()?.flush()?;

    Ok(())
}

fn hit_regions_with_seq(
    hit_regions: &[hdb::HitRegion],
    seq: &[NucleotideAmbiguous],
    provenance: Provenance,
) -> Vec<HitRegion> {
    hit_regions
        .iter()
        .map(|hr| {
            let seq = DnaSequenceAmbiguous::new(seq[hr.seq_range_start..hr.seq_range_end].to_vec());
            let seq = if provenance.is_dna() {
                seq.to_string()
            } else {
                seq.translate(TranslationTable::Ncbi1).to_string()
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
    info!("Using DB {:?}", opts.hdb_dir);

    let database = Database::open(opts.hdb_dir.clone()).expect("failed to open database");
    let hlt = HazardLookupTable::read(&opts.hdb_dir).expect("failed to open HLT");

    let parser = FastaParser::<DnaSequence<NucleotideAmbiguous>>::new(
        FastaParseSettings::new()
            .concatenate_headers(true)
            .allow_preceding_comment(false),
    );

    let debug_dirs = opts
        .debug
        .then(|| -> anyhow::Result<_> {
            // these are the directories the debug .gz files are stored in. One for with rs, one
            // with no rs
            let with_rs = format!("./debug-output-{start_time_str}.with-rs");
            let no_rs = format!("./debug-output-{start_time_str}.no-rs");
            fs::create_dir_all(&with_rs)
                .with_context(|| format!("creating debug dir {with_rs}"))?;
            fs::create_dir_all(&no_rs).with_context(|| format!("creating debug dir {no_rs}"))?;
            Ok(DebugDirs { with_rs, no_rs })
        })
        .transpose()?;

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
                    &opts.secret_key,
                    r,
                    debug_dirs.as_ref(),
                    AhaCheckerConfiguration {
                        debug: opts.debug,
                        summary: opts.summary,
                        generate_dna_windows: !opts.no_dna,
                        generate_runt_windows: !opts.no_runts,
                        generate_aa_windows: !opts.no_aa,
                        max_expansions_per_window: opts.expansions_limit,
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
            None,
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
            None,
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
            None,
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
                None,
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
            check_one_record(
                &database,
                &hlt,
                &ks,
                r,
                None,
                AhaCheckerConfiguration::default(),
            )
            .unwrap(),
            (
                Some("Nonmatching".into()),
                Some(SummaryLine {
                    synthesis_permission: SummaryPermissions {
                        no_region: SynthesisPermission::Granted,
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
                    true_likely_organisms: "".into(),
                    true_likely_ans: "".into(),
                    rs_likely_organisms: "".into(),
                    rs_likely_ans: "".into()
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
                None,
                AhaCheckerConfiguration::default(),
            )
            .unwrap(),
            (
                None,
                Some(SummaryLine {
                    synthesis_permission: SummaryPermissions {
                        no_region: SynthesisPermission::Denied,
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
                    true_likely_organisms: "Minimal organism".into(),
                    true_likely_ans: "AN1000000.1".into(),
                    rs_likely_organisms: "".into(),
                    rs_likely_ans: "".into()
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
                None,
                AhaCheckerConfiguration {
                    generate_runt_windows: false,
                    generate_aa_windows: false,
                    ..Default::default()
                }
            )
            .unwrap(),
            (
                None,
                Some(SummaryLine {
                    synthesis_permission: SummaryPermissions {
                        no_region: SynthesisPermission::Denied,
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
                    true_likely_organisms: "Minimal organism".into(),
                    true_likely_ans: "AN1000000.1".into(),
                    rs_likely_organisms: "".into(),
                    rs_likely_ans: "".into()
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
                None,
                AhaCheckerConfiguration {
                    generate_dna_windows: false,
                    generate_runt_windows: false,
                    ..Default::default()
                }
            )
            .unwrap(),
            (
                None,
                Some(SummaryLine {
                    synthesis_permission: SummaryPermissions {
                        no_region: SynthesisPermission::Denied,
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
                    true_likely_organisms: "Minimal organism".into(),
                    true_likely_ans: "AN1000000.1".into(),
                    rs_likely_organisms: "".into(),
                    rs_likely_ans: "".into()
                })
            )
        );
    }

    #[test]
    fn test_csv_output() {
        let summary_line = SummaryLine {
            synthesis_permission: SummaryPermissions {
                no_region: SynthesisPermission::Denied,
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
            true_likely_organisms: "true likely;organisms".into(),
            true_likely_ans: "AN_12345".into(),
            rs_likely_organisms: "rs likely".into(),
            rs_likely_ans: "AN_56789".into(),
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
            "denied,denied,granted,denied,123,4,56,78,9,0,\"red,name\",true likely;organisms,AN_12345,rs likely,AN_56789\n",
        );
    }
}
