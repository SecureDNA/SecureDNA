// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::shared::config::Config;
use anyhow::Context;
use csv::Writer;
use itertools::Itertools;
use serde_json;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SummaryLine {
    stat: String,
    baseline: f32,
    new: f32,
    difference: f32,
}

impl SummaryLine {
    pub fn write_header<W: Write>(wtr: &mut Writer<W>) -> anyhow::Result<()> {
        wtr.write_record(["STAT", "BASELINE", "NEW", "% DIFFERENCE"])
            .context("writing header")
    }

    pub fn write<W: Write>(&self, wtr: &mut Writer<W>) -> anyhow::Result<()> {
        wtr.write_record([
            self.stat.as_str(),
            &format!("{:.2}", self.baseline),
            &format!("{:.2}", self.new),
            &format!("{:.2}", self.difference),
        ])
        .with_context(|| format!("writing record: {}", self.stat))
    }
}

/// Write out the summary in CSV format to the results directory
pub fn goose_stats_writecsv(
    baseline_stats: &HashMap<String, f32>,
    new_stats: Option<&HashMap<String, f32>>,
    dir: PathBuf,
) -> anyhow::Result<()> {
    let filename = dir.join("summary.csv");
    let mut wtr = Writer::from_path(filename)?;
    SummaryLine::write_header(&mut wtr)?;

    for key in baseline_stats.keys().sorted() {
        let value = baseline_stats.get(key).unwrap();
        let (new, difference) = match new_stats {
            Some(new_stats) => {
                let value2 = new_stats
                    .get(key)
                    .expect("stat maps do not contain the same keys");
                let diff = value2 / value - 1.0;
                (*value2, diff)
            }
            None => (-1.0, -1.0),
        };
        let line = SummaryLine {
            stat: key.clone(),
            baseline: *value,
            new,
            difference,
        };
        line.write(&mut wtr)?;
    }

    Ok(())
}

fn print_metrics(t1: &HashMap<String, f32>, t2: Option<&HashMap<String, f32>>, metrics: Vec<&str>) {
    for metric in metrics {
        let t1_x = t1.get(metric).unwrap();
        if let Some(t2) = t2 {
            let t2_x = t2.get(metric).unwrap();
            let difference = (t2_x / t1_x - 1.0) * 100.0;
            println!("{metric: <10}{t1_x:<10.2}{t2_x:<10.2}{difference:<10.2}%");
        } else {
            println!("{metric: <10}{t1_x:<10.2}");
        }
    }
}

/// Pretty print short summary to console
pub fn tpt_stats_prettyprint(
    t1: &HashMap<String, f32>,
    t2: Option<&HashMap<String, f32>>,
    config: &Config,
) {
    let value = serde_json::to_value(config).unwrap();
    let config_map: BTreeMap<String, String> = match value.as_object() {
        Some(map) => map
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_string()))
            .collect(),
        None => BTreeMap::new(),
    };
    let separator: String = "-".repeat(41);
    println!("{separator}");
    println!("Config Dump:");

    for (key, value) in config_map.iter() {
        println!("{}: {}", key, value);
    }

    println!("{separator}");

    if t2.is_some() {
        println!(
            "{0: <10}{1:<10}{2:<10}{3:<10}%",
            "Stat", "Baseline", "New", "Difference"
        );
    } else {
        println!("{0: <10}{1:<10}", "Stat", "Baseline");
    }

    let tpt_metrics = ["hash_s", "bp_s"];
    let latency_metrics = ["min_ms", "median_ms", "mean_ms", "max_ms", "spread"];
    let failure_metrics = ["fail_rt"];

    println!("{separator}\nThroughput");
    print_metrics(t1, t2, tpt_metrics.to_vec());
    println!("{separator}\nLatency");
    print_metrics(t1, t2, latency_metrics.to_vec());
    println!("{separator}\nFailure Rate");
    print_metrics(t1, t2, failure_metrics.to_vec());
}
