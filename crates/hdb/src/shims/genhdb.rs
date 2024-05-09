// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{prelude::*, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::Context;
use bitvec::prelude::{bitvec, Msb0};
use clap::{crate_version, Parser, Subcommand};
use flate2::bufread::GzDecoder;
use itertools::Itertools;
use rayon::prelude::*;
use tracing::info;

use crate::database::Database;
use crate::hlt::{HazardLookupTable, HltEntry, HltId};
use crate::{tags, Entry};
use crate::{Metadata, Provenance};
use doprf::prf::{KeyShare, Query};
use pipeline_bridge::{self as pb, BuildTrace, DNA_NORMAL_LEN, DNA_RUNT_LEN};

const BUILD_INFO_FILENAME: &str = "BUILD_INFO.json";

#[derive(Debug, Parser)]
#[clap(
    name = "genhdb",
    about = "Generates SecureDNA hashed database",
    version = crate_version!()
)]
pub struct Opts {
    #[clap(help = "the randomly generated secret key to use to generate")]
    pub secret_key: KeyShare,

    #[clap(help = "the location of the artifacts dir")]
    pub artifacts_dir: PathBuf,

    #[clap(help = "where to put the database (as a directory)")]
    pub database: PathBuf,

    #[command(subcommand)]
    pub command: Command,

    #[clap(
        short,
        long,
        help = "number of threads to use for hashing (default 128)",
        default_value = "128"
    )]
    pub num_threads: usize,

    #[clap(
        long,
        help = "only sort an existing database, instead of generating a new one"
    )]
    pub sort_only: bool,

    #[clap(
        short,
        long,
        help = "Memory used for database indexes, in megabytes",
        default_value = "1024"
    )]
    pub index_mb: u16,

    #[clap(
        short,
        long,
        help = "Skip copying/updating build info in hdb. Necessary for pipeline tests, which don't pick up build info from test build environment"
    )]
    pub skip_build_info: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    New {
        #[clap(
            short,
            long,
            help = "whether to overwrite the database directory if it already exists"
        )]
        force: bool,
    },
    Update,
}

const BATCH_SIZE: usize = 1 << 20;

/// Tries to open a given path to a BufRead
/// First checks if the given path + ".gz" exists, and if so decompresses with flate2
/// If not, returns a plain BufRead
pub fn open_file_maybe_gz(path: &Path) -> anyhow::Result<Box<dyn BufRead>> {
    // Option 1) The path provided has the .gz extension
    let file_has_gz_extension = if let Some(ext) = path.extension() {
        ext == "gz"
    } else {
        false
    };
    if file_has_gz_extension {
        return Ok(Box::new(BufReader::new(GzDecoder::new(BufReader::new(
            File::open(path).with_context(|| format!("failed to open gz path {path:?}"))?,
        )))));
    }

    // Option 2) The path provided does not have a .gz extension but such a file exists
    let with_gz = path.with_extension({
        let mut new_ext = path
            .extension()
            .map(|oss| oss.to_os_string())
            .unwrap_or_default();
        new_ext.push(OsString::from(".gz"));
        new_ext
    });
    if with_gz.exists() {
        return Ok(Box::new(BufReader::new(GzDecoder::new(BufReader::new(
            File::open(&with_gz).with_context(|| format!("failed to open gz path {with_gz:?}"))?,
        )))));
    }

    // Option 3) the path is not compressed
    Ok(Box::new(BufReader::new(File::open(path).with_context(
        || format!("failed to open path {path:?}"),
    )?)))
}

/// Helper to take the best metadata from a possibly-absent incumbent and a candidate
fn select_best_metadata(
    current: Option<Metadata>,
    candidate: Metadata,
    hlt: &HazardLookupTable,
) -> Metadata {
    fn quality(metadata: &Metadata, hlt: &HazardLookupTable) -> impl std::cmp::PartialOrd {
        // We prefer things that, in order of priority...
        (
            // 1. aren't reversed screened (highest priority)
            !metadata.reverse_screened,
            // 2. aren't low risk DNA
            // (panic safety: it would be a bug for the metadata to be invalid here,
            //  it would mean we had generated an inconsistent HLT)
            !tags::metadata_is_low_risk_dna(metadata, hlt).unwrap(),
            // 3. have higher an_likelihood (lowest priority)
            metadata.an_likelihood,
        )
    }

    match current {
        // Beware: quality is PartialOrd so simplification will likely change logic
        Some(current) if quality(&current, hlt) < quality(&candidate, hlt) => candidate,
        Some(current) => current,
        None => candidate,
    }
}

fn merge_entries(entries: &[Entry], hlt: &mut HazardLookupTable) -> anyhow::Result<Entry> {
    let mut hlt_indexes = Vec::with_capacity(entries.len());
    let mut highest_likelihood_metadata: Option<Metadata> = None;
    for e in entries {
        let m = e.metadata().context("failed to decode metadata")?;
        highest_likelihood_metadata =
            Some(select_best_metadata(highest_likelihood_metadata, m, hlt));
        hlt_indexes.push(m.hlt_index);
    }
    let highest_likelihood_metadata = highest_likelihood_metadata.unwrap();

    let new_hlt_index = hlt
        .merge(&hlt_indexes)
        .context("failed to merge HLT indexes")?;
    let new_an_subindex: u8 = hlt
        .get(&new_hlt_index)
        .unwrap()
        .index_of(
            hlt.get(&highest_likelihood_metadata.hlt_index)
                .context("missing HLT entry for most-likely metadata")?
                .get(highest_likelihood_metadata.an_subindex)
                .ok_or_else(|| {
                    anyhow::anyhow!("missing a subindex in HLT entry for most-likely metadata")
                })?,
        )
        .context("merge did not include an_subindex entry")?;

    Ok(Entry::new(
        entries[0].hash_part().map_err(anyhow::Error::msg)?,
        Metadata {
            hlt_index: new_hlt_index,
            an_subindex: new_an_subindex,
            an_likelihood: highest_likelihood_metadata.an_likelihood,
            provenance: highest_likelihood_metadata.provenance,
            reverse_screened: highest_likelihood_metadata.reverse_screened,
            is_common: highest_likelihood_metadata.is_common,
        },
    ))
}

/// Consumes `entries`, which must be sorted. Scans for runs of duplicate entries
/// and merges them, returning an iterator of the merged entries.
fn sort_and_merge_db_file_vec(
    mut entries: Vec<Entry>,
    hlt: &mut HazardLookupTable,
) -> anyhow::Result<impl Iterator<Item = Entry>> {
    entries.par_sort_unstable();

    // this holds the indices of merged entries (not first in their run) that should be dropped
    let mut dropped = bitvec![u8, Msb0; 0; entries.len()];

    let mut index = 0;
    while index < entries.len() {
        let run_start = index;
        let run_start_hash = entries[run_start].hash_slice();
        while index < entries.len() && entries[index].hash_slice() == run_start_hash {
            // continuously advance index through the run until it's at the end of the vec,
            // or pointing at an element with a different hash than run_start_hash
            index += 1;
        }
        // index points 1 past the end of the run of duplicates (which may only be a single-
        // element "run")
        if index - run_start > 1 {
            // we have duplicates!
            for i in run_start + 1..index {
                dropped.set(i, true);
            }
            entries[run_start] = merge_entries(&entries[run_start..index], hlt)?;
        }
    }

    Ok(entries
        .into_iter()
        .enumerate()
        .filter(move |(i, _)| !dropped.get(*i).unwrap())
        .map(|(_, e)| e))
}

pub fn get_entry_file_paths(
    root: &Path,
) -> anyhow::Result<impl Iterator<Item = std::io::Result<PathBuf>>> {
    Ok(std::fs::read_dir(root)
        .with_context(|| format!("Failed to read directory {}", root.display()))?
        .filter(|de| {
            if let Ok(de) = de {
                let is_file = de.file_type().unwrap().is_file();
                let is_index_file =
                    de.path().extension().map(|ext| ext.to_string_lossy()) == Some("i".into());
                let is_hlt = de.file_name().to_str() == Some("hlt.json");
                let is_buildinfo = de.file_name().to_str() == Some(BUILD_INFO_FILENAME);
                is_file && !is_hlt && !is_index_file && !is_buildinfo
            } else {
                false
            }
        })
        .map(|res| res.map(|de| de.path())))
}

#[tracing::instrument]
pub fn sort_db_files(prefix: &Path, hlt: &mut HazardLookupTable) -> anyhow::Result<()> {
    let paths = get_entry_file_paths(prefix)?;

    for path in paths {
        let path = path.context("failed to read db dir")?;

        let contents = Entry::read_all_from_reader(BufReader::new(File::open(&path)?))
            .with_context(|| format!("failed to read hdb hash file {:?}", path))?;
        let contents = sort_and_merge_db_file_vec(contents, hlt)?;

        let file = OpenOptions::new().write(true).truncate(true).open(&path)?;
        let mut writer = BufWriter::new(file);

        for c in contents {
            writer.write_all(&c.bytes)?;
        }
    }
    Ok(())
}

#[tracing::instrument]
pub fn index_db_files(prefix: &Path, index_mb: u16) -> anyhow::Result<()> {
    let index_bytes = index_mb as usize * 1024 * 1024;
    Database::rebuild_index(prefix, index_bytes).context("failed to index database")?;
    Ok(())
}

fn hash_chunk(
    key: &KeyShare,
    chunk: Vec<std::io::Result<String>>,
    hlt_index: u32,
    an_subindex: u8,
) -> anyhow::Result<Vec<Entry>> {
    let mut hash_metas = vec![];

    for line in chunk.into_iter() {
        let line = line.context("failed to read line")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let pb::VariantEntry {
            variant,
            provenance,
            log_likelihood,
            reverse_screened,
            is_common,
        } = serde_json::from_str(line).context("failed to deserialize entry")?;

        let metadata = Metadata {
            hlt_index,
            an_subindex,
            an_likelihood: log_likelihood
                .map(half::f16::from_f32)
                .unwrap_or(half::f16::ZERO),
            provenance: match provenance {
                Some(pb::Provenance::WildType) => Provenance::AAWildType,
                Some(pb::Provenance::SingleReplacement) => Provenance::AASingleReplacement,
                Some(pb::Provenance::DoubleReplacement) => Provenance::AADoubleReplacement,
                Some(pb::Provenance::MHSample) => Provenance::AASampled,
                // If provenance is None, then it's DNA—but we need to determine which
                // kind based on the length
                None => match variant.len() {
                    DNA_NORMAL_LEN => Provenance::DnaNormal,
                    DNA_RUNT_LEN => Provenance::DnaRunt,
                    len => anyhow::bail!("unknown dna length: {len}"),
                },
            },
            reverse_screened: reverse_screened.is_some(),
            is_common,
        };

        let hash_part = key.apply(Query::hash_from_string(&variant));
        hash_metas.push(Entry::new(hash_part, metadata));
    }

    Ok(hash_metas)
}

#[tracing::instrument(skip_all)]
fn hash_file(opts: &Opts, fraglist: &Path, hlt_index: u32, an_subindex: u8) -> anyhow::Result<()> {
    let reader = open_file_maybe_gz(fraglist)?;
    let mut entries_by_prefix: Vec<Vec<Entry>> = vec![vec![]; 256];

    info!("* Hashing {:?}", fraglist);
    for (idx, line_iter) in reader.lines().chunks(BATCH_SIZE).into_iter().enumerate() {
        info!("Reading a batch ({} lines)", (idx + 1) * BATCH_SIZE);
        let mut handles = vec![];

        let num_sub_batches = BATCH_SIZE / opts.num_threads + 1;
        for chunk in line_iter.chunks(num_sub_batches).into_iter() {
            let chunk = chunk.collect::<Vec<std::io::Result<String>>>();
            let key = opts.secret_key;
            handles.push(std::thread::spawn(move || {
                hash_chunk(&key, chunk, hlt_index, an_subindex)
            }))
        }

        for join_handle in handles {
            for db_entry in join_handle.join().unwrap()? {
                // NOTE: this is tied to the prefix length, so if it changes this needs
                // to be updated as well
                entries_by_prefix[db_entry.bytes[0] as usize].push(db_entry);
            }
        }

        info!("Writing to files");
        // this loop clears hashes_by_prefix for the next batch as it mem::takes each non-empty prefix
        for (i, prefix_addendum) in entries_by_prefix.iter_mut().enumerate() {
            if !prefix_addendum.is_empty() {
                let suffixes = std::mem::take(prefix_addendum);

                let filename = {
                    let mut filename = opts.database.clone();
                    filename.push(hex::encode((i as u8).to_be_bytes()));
                    filename
                };
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&filename)
                    .with_context(|| format!("failed to open {filename:?} for appending"))?;

                let mut writer = BufWriter::new(f);

                for l in suffixes.into_iter() {
                    writer
                        .write_all(&l.bytes)
                        .with_context(|| format!("failed to write to db file {filename:?}"))?;
                }
            }
        }
    }

    Ok(())
}

#[tracing::instrument(skip_all)]
fn generate(opts: &Opts, mut hlt: HazardLookupTable) -> anyhow::Result<HazardLookupTable> {
    info!("* Reading aggregation file");
    let file = open_file_maybe_gz(&opts.artifacts_dir.as_path().join("aggregated.json"))
        .with_context(|| "Failed to read aggregated.json")?;
    let aggregated: Vec<pb::AggregatedHazard> = serde_json::from_reader(BufReader::new(file))
        .with_context(|| "Failed to read aggregated.json")?;

    for hazard in aggregated {
        let hazard_meta = hazard.hazard_meta;

        // we group all the accessions together for this organism, since we want the an_subindex to
        // point to the whole organism, since we don't have per-hazard accession data currently.
        let entry = {
            let mut hlt_id_group: Vec<HltId> = hazard_meta
                .accessions
                .iter()
                .map(|s| HltId::Accession(s.clone()))
                .collect();

            hlt_id_group.push(HltId::OrganismName(hazard_meta.common_name.clone()));

            hlt_id_group.extend(hazard_meta.tags.iter().map(|s| HltId::Tag(*s)));

            if hazard_meta.tiled {
                hlt_id_group.push(HltId::Tiled);
            }

            hlt_id_group.push(HltId::OrganismType(hazard_meta.organism_type));

            HltEntry::new(vec![hlt_id_group])
        };
        let hazard_hlt_index = hlt.insert(entry);
        let an_subindex = 0_u8;

        for path in &[
            hazard.protein_variants_path,
            hazard.dna_variant_42mers_path,
            hazard.dna_variant_30mers_path,
        ] {
            hash_file(
                opts,
                opts.artifacts_dir.join(path).as_ref(),
                hazard_hlt_index,
                an_subindex,
            )?;
        }
    }

    Ok(hlt)
}

fn initialize(opts: &Opts) -> anyhow::Result<HazardLookupTable> {
    Ok(match opts.command {
        Command::New { force } => {
            info!("* Initializing new hdb");
            if std::fs::metadata(&opts.database).is_ok() {
                if force {
                    info!("* Removing existing directory (--force)");
                    std::fs::remove_dir_all(&opts.database)
                        .with_context(|| "Failed to delete database dir.")?;
                } else {
                    return Err(anyhow::Error::new(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "database directory already exists. use --force to force-remove"
                            .to_string(),
                    )));
                }
            }
            info!("* Creating empty hdb at {}", opts.database.display());
            std::fs::create_dir(&opts.database).with_context(|| "Failed to create database dir")?;
            info!("* Opening empty HazardLookupTable");
            HazardLookupTable::default()
        }
        Command::Update => {
            info!("* Updating existing hdb at {}", opts.database.display());
            HazardLookupTable::read(&opts.database)?
        }
    })
}

fn copy_update_build_info(opts: &Opts) -> anyhow::Result<()> {
    if !opts.skip_build_info {
        let new_buildinfo_path = opts.artifacts_dir.join(BUILD_INFO_FILENAME);
        let cur_buildinfo_path = opts.database.join(BUILD_INFO_FILENAME);
        match opts.command {
            Command::New { .. } => {
                info!("Copying BUILD_INFO.json from artifacts dir");
                std::fs::copy(new_buildinfo_path, cur_buildinfo_path)?;
            }
            Command::Update => {
                info!("Updating BUILD_INFO.json in target hdb using BUILD_INFO.json from artifacts dir");
                // add most recent build info to head of trace list
                let mut new_buildinfo: BuildTrace =
                    serde_json::from_reader(File::open(&new_buildinfo_path)?)?;
                let cur_buildinfo: BuildTrace =
                    serde_json::from_reader(File::open(&cur_buildinfo_path)?)?;
                new_buildinfo.previous_build_info = Some(Box::new(cur_buildinfo));
                std::fs::write(
                    cur_buildinfo_path,
                    serde_json::to_string_pretty(&new_buildinfo)?,
                )?
            }
        }
    }

    Ok(())
}

pub fn main(opts: &Opts) -> anyhow::Result<()> {
    let mut hlt = if !opts.sort_only {
        info!("* Initializing database");
        let hlt = initialize(opts)?;
        info!("* Generating database");
        generate(opts, hlt)?
    } else {
        info!("* Reading HLT");
        HazardLookupTable::read(&opts.database).context("failed to open HLT")?
    };

    info!("* Sorting files");
    sort_db_files(&opts.database, &mut hlt)?;

    info!("* Indexing files");
    index_db_files(&opts.database, opts.index_mb)?;

    info!("* Writing HLT");
    hlt.write(&opts.database).context("failed to write HLT")?;

    info!("* Copying/updating BUILD_INFO.json");
    copy_update_build_info(opts)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::prelude::*;

    use doprf::prf::HashPart;

    use super::*;
    use Provenance;

    fn hash(seed: u8) -> HashPart {
        let mut bytes = [0_u8; 32];
        bytes[0] = seed;
        HashPart::hash_from_bytes_for_tests_only(&bytes[..])
    }

    fn meta(
        hlt_index: u32,
        an_subindex: u8,
        an_likelihood: f32,
        provenance: Provenance,
        reverse_screened: bool,
    ) -> Metadata {
        Metadata {
            hlt_index,
            an_subindex,
            an_likelihood: half::f16::from_f32(an_likelihood),
            provenance,
            reverse_screened,
            // is_common does not affect genhdb logic, so not needed as a param in `meta`.
            // Better to test in integration test
            is_common: false,
        }
    }

    fn get_hdb_vec_entry_by_hash(entries: &[Entry], hash: HashPart) -> Option<&Entry> {
        entries
            .iter()
            .find(|e| e.hash_bytes() == <[u8; 32]>::from(hash))
    }

    /// Poor-man's property testing for db order.
    /// Since merging is sensitive to order, we seeded-shuffle the db and
    /// run 1+100 times (once with the original order, 100 shuffled).
    /// The HLT will be cloned for each iteration.
    fn db_shuffle_runner(
        base_hlt: &HazardLookupTable,
        mut hdb: Vec<Entry>,
        mut test: impl FnMut(HazardLookupTable, &Vec<Entry>),
    ) {
        let mut rand = rand::rngs::StdRng::from_seed([0xba; 32]);
        for _ in 0..100 {
            test(base_hlt.clone(), &hdb);
            // we shuffle after so the first time gets the user-given order, if it has significance
            hdb.shuffle(&mut rand);
        }
        test(base_hlt.clone(), &hdb); // use that last shuffle
    }

    #[test]
    fn merge_entries_merges_highest_likelihood() {
        let base_hlt: HazardLookupTable = serde_json::from_str(
            r#"
            {
                "entries": {
                    "0": { "id_groups": [[{"OrganismName": "Nerve Attenuation Syndrome"}, {"Accession": "NC_019843.3"}]] }
                }
            }
            "#,
        )
        .unwrap();

        let hdb = vec![
            Entry::new(
                hash(1),
                meta(0, 0, 0.0, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(
                hash(1),
                meta(0, 0, 0.1, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(
                hash(1),
                meta(0, 0, 0.2, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(
                hash(1),
                meta(0, 0, 0.3, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(hash(1), meta(0, 0, 0.4, Provenance::AAWildType, false)),
            // should prefer non-reverse-screened entry
            Entry::new(hash(1), meta(0, 0, 0.5, Provenance::AAWildType, true)),
        ];

        db_shuffle_runner(&base_hlt, hdb, |mut hlt, hdb| {
            let merged = merge_entries(&hdb[..], &mut hlt).expect("failed to merge");
            assert_eq!(base_hlt.len(), hlt.len()); // shouldn't make a new entry since indices are the same
            assert_eq!(
                merged,
                Entry::new(hash(1), meta(0, 0, 0.4, Provenance::AAWildType, false))
            );
        });
    }

    #[test]
    fn merge_entries_takes_highest_likelihood_reverse_screened() {
        let base_hlt: HazardLookupTable = serde_json::from_str(
            r#"
            {
                "entries": {
                    "0": { "id_groups": [[{"OrganismName": "Hyperplague"}, {"Accession": "NC_019843.3"}]] }
                }
            }
            "#,
        )
        .unwrap();

        let hdb = vec![
            Entry::new(
                hash(1),
                meta(0, 0, 0.0, Provenance::AADoubleReplacement, true),
            ),
            Entry::new(
                hash(1),
                meta(0, 0, 0.1, Provenance::AADoubleReplacement, true),
            ),
            Entry::new(
                hash(1),
                meta(0, 0, 0.2, Provenance::AADoubleReplacement, true),
            ),
            Entry::new(
                hash(1),
                meta(0, 0, 0.3, Provenance::AADoubleReplacement, true),
            ),
            Entry::new(hash(1), meta(0, 0, 0.4, Provenance::AAWildType, true)),
            // should prefer non-reverse-screened entry
            Entry::new(hash(1), meta(0, 0, 0.5, Provenance::AAWildType, true)),
        ];

        db_shuffle_runner(&base_hlt, hdb, |mut hlt, hdb| {
            let merged = merge_entries(&hdb[..], &mut hlt).expect("failed to merge");
            assert_eq!(base_hlt.len(), hlt.len()); // shouldn't make a new entry since indices are the same
            assert_eq!(
                merged,
                Entry::new(hash(1), meta(0, 0, 0.5, Provenance::AAWildType, true))
            );
        });
    }

    #[test]
    fn merge_entries_prefers_low_risk_over_rs() {
        let base_hlt: HazardLookupTable = serde_json::from_str(
            r#"
            {
                "entries": {
                    "0": { "id_groups": [
                        [{"OrganismName": "Hyperplague"}, {"Accession": "NC_019843.3"}],
                        [{"OrganismName": "Mehplague"}, {"Accession": "NC_020843.3"}, {"Tag": "SdnaLowRiskDNA"}]
                    ] }
                }
            }
            "#,
        )
        .unwrap();

        let hdb = vec![
            Entry::new(hash(1), meta(0, 0, 0.0, Provenance::DnaNormal, true)),
            Entry::new(hash(1), meta(0, 1, 0.0, Provenance::DnaNormal, false)),
        ];

        db_shuffle_runner(&base_hlt, hdb, |mut hlt, hdb| {
            let merged = merge_entries(&hdb[..], &mut hlt).expect("failed to merge");
            assert_eq!(base_hlt.len(), hlt.len()); // shouldn't make a new entry since indices are the same
            assert_eq!(
                merged,
                Entry::new(hash(1), meta(0, 1, 0.0, Provenance::DnaNormal, false))
            );
        });
    }

    #[test]
    fn merge_entries_prefers_non_low_risk() {
        let base_hlt: HazardLookupTable = serde_json::from_str(
            r#"
            {
                "entries": {
                    "0": { "id_groups": [
                        [{"OrganismName": "Hyperplague"}, {"Accession": "NC_019843.3"}],
                        [{"OrganismName": "Mehplague"}, {"Accession": "NC_020843.3"}, {"Tag": "SdnaLowRiskDNA"}]
                    ] }
                }
            }
            "#,
        )
        .unwrap();

        let hdb = vec![
            Entry::new(hash(1), meta(0, 0, 0.0, Provenance::DnaNormal, false)),
            Entry::new(hash(1), meta(0, 1, 0.1, Provenance::DnaNormal, false)),
        ];

        db_shuffle_runner(&base_hlt, hdb, |mut hlt, hdb| {
            let merged = merge_entries(&hdb[..], &mut hlt).expect("failed to merge");
            assert_eq!(base_hlt.len(), hlt.len()); // shouldn't make a new entry since indices are the same
            assert_eq!(
                merged,
                Entry::new(hash(1), meta(0, 0, 0.0, Provenance::DnaNormal, false))
            );
        });
    }

    static COMPLICATED_HLT: &str = r#"
    {
        "entries": {
            "0": { "id_groups": [
                [{"OrganismName": "Nastyitis"}, {"Accession": "NC_00000.0"}, {"Accession": "NC_00000.1"}],
                [{"Accession": "NC_00001"}]
            ] },
            "198": { "id_groups": [[{"Accession": "NC_00002"}]] }
        }
    }
    "#;

    #[test]
    fn merge_entries_merges_hlt() {
        let base_hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();

        let hdb = vec![
            Entry::new(
                hash(1),
                meta(0, 0, 0.0, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(
                hash(1),
                meta(0, 1, 0.1, Provenance::AADoubleReplacement, true),
            ),
            Entry::new(
                hash(1),
                meta(198, 0, 0.2, Provenance::AADoubleReplacement, false),
            ),
        ];

        db_shuffle_runner(&base_hlt, hdb, |mut hlt, hdb| {
            let merged = merge_entries(&hdb[..], &mut hlt).expect("failed to merge");
            let merged_meta = merged.metadata().expect("failed to parse merged metadata");
            assert_eq!(
                merged,
                Entry::new(
                    hash(1),
                    meta(
                        merged_meta.hlt_index,
                        merged_meta.an_subindex,
                        0.2,
                        Provenance::AADoubleReplacement,
                        false
                    )
                )
            );
            assert_eq!(hlt.len(), 3);
            let merged_hlt_entry = hlt
                .get(&merged_meta.hlt_index)
                .expect("hlt missing merged hlt_index");
            assert_eq!(
                merged_hlt_entry
                    .get(merged_meta.an_subindex)
                    .expect("merged meta HLT entry missing merged an_subindex"),
                &vec![HltId::Accession("NC_00002".into())]
            );
            assert_eq!(hlt.get(&0), base_hlt.get(&0));
            assert_eq!(hlt.get(&198), base_hlt.get(&198));
        });
    }

    #[test]
    fn sort_merge_keeps_all() {
        let mut hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();

        let hdb = vec![
            Entry::new(
                hash(1),
                meta(0, 0, 0.0, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(
                hash(2),
                meta(0, 1, 0.1, Provenance::AADoubleReplacement, true),
            ),
            Entry::new(
                hash(3),
                meta(198, 0, 0.2, Provenance::AADoubleReplacement, false),
            ),
        ];

        let merged: Vec<_> = sort_and_merge_db_file_vec(hdb.clone(), &mut hlt)
            .unwrap()
            .collect();

        assert_eq!(merged.len(), 3);
        for orig_entry in hdb.iter() {
            assert!(merged.iter().any(|e| e == orig_entry));
        }
        assert_eq!(hlt.len(), 2);
    }

    #[test]
    fn sort_merge_merges() {
        let mut hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();

        // hash(2) < hash(4) < hash(5)

        let hdb = vec![
            Entry::new(hash(4), meta(0, 1, 0.2, Provenance::AASampled, false)),
            Entry::new(
                hash(2),
                meta(0, 0, 0.0, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(
                hash(4),
                meta(0, 1, 0.1, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(
                hash(5),
                meta(198, 0, 0.2, Provenance::AADoubleReplacement, false),
            ),
            Entry::new(hash(4), meta(198, 0, 0.5, Provenance::AAWildType, false)),
            Entry::new(
                hash(5),
                meta(0, 1, 0.3, Provenance::AADoubleReplacement, true),
            ),
        ];

        let merged: Vec<_> = sort_and_merge_db_file_vec(hdb.clone(), &mut hlt)
            .unwrap()
            .collect();

        assert_eq!(merged.len(), 3);
        assert_eq!(hlt.len(), 3); // should have added one for the hash(4) merge
                                  // shouldn't change entries that are only one of their hash
        assert_eq!(
            get_hdb_vec_entry_by_hash(&merged, hash(2)).unwrap(),
            &hdb[1]
        );
        // should have merged all the hash(4) entries
        let merged_hash4 = get_hdb_vec_entry_by_hash(&merged, hash(4)).unwrap();
        let merged_hash4_meta = merged_hash4.metadata().unwrap();
        let merged_hash4_hlt = hlt.get(&merged_hash4_meta.hlt_index).unwrap();
        assert_eq!(merged_hash4_hlt.len(), 3);
        assert_eq!(merged_hash4_meta.an_likelihood, half::f16::from_f32(0.5));
        assert_eq!(merged_hash4_meta.provenance, Provenance::AAWildType);
        assert!(!merged_hash4_meta.reverse_screened);
        // should have merged all the hash(5) entries
        let merged_hash5 = get_hdb_vec_entry_by_hash(&merged, hash(5)).unwrap();
        let merged_hash5_meta = merged_hash5.metadata().unwrap();
        // shouldn't have made a new HLT entry, should share
        assert_eq!(merged_hash4_meta.hlt_index, merged_hash5_meta.hlt_index);
        // shouldn't have picked the reverse_screened: true entry
        assert_eq!(merged_hash5_meta.an_likelihood, half::f16::from_f32(0.2));
        assert_eq!(
            merged_hash5_meta.provenance,
            Provenance::AADoubleReplacement
        );
        assert!(!merged_hash5_meta.reverse_screened);
    }

    #[test]
    fn sort_merge_doesnt_lose_any() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xf0015abad533d);

        for _ in 0..100 {
            let mut hlt: HazardLookupTable = serde_json::from_str(COMPLICATED_HLT).unwrap();

            let template: Vec<(u8, usize)> = {
                // hash(0)..=hash(9) has no collisions
                let n_seeds = rng.gen_range(2..=10);
                (0..=9)
                    .collect::<Vec<_>>()
                    .choose_multiple(&mut rng, n_seeds)
                    .map(|&seed| {
                        let amount = rng.gen_range(1..20);
                        (seed, amount)
                    })
                    .collect::<Vec<_>>()
            };

            let hdb: Vec<_> = {
                let mut hdb: Vec<_> = template
                    .iter()
                    .flat_map(|(seed, amount)| {
                        (0..*amount).map(|_| {
                            Entry::new(hash(*seed), meta(0, 0, 0., Provenance::DnaNormal, false))
                        })
                    })
                    .collect();
                hdb.shuffle(&mut rng);
                hdb
            };

            let merged: Vec<_> = sort_and_merge_db_file_vec(hdb, &mut hlt).unwrap().collect();

            if merged.len() != template.len() {
                eprintln!("(template: [");
                for (seed, amount) in template.iter() {
                    eprintln!("  hash({seed}) x {amount},");
                }
                eprintln!("])");
                panic!("did not generate the correct number of entries from template: should have {}, got {} entries", template.len(), merged.len());
            }
        }
    }
}
