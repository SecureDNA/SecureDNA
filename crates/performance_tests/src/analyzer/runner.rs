// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::path::PathBuf;

use crate::analyzer::pushgateway::send_pushgateway;
use crate::analyzer::stats::calc_goose;
use crate::analyzer::writer::{goose_stats_writecsv, tpt_stats_prettyprint};
use crate::shared::config::Config;
use anyhow::anyhow;
use goose::metrics::GooseMetrics;

pub fn extract_goose_metrics(metrics: &GooseMetrics, config: &Config) -> HashMap<String, f32> {
    calc_goose(metrics, config.hash_count)
}

pub fn print_metrics_comparison(
    path: PathBuf,
    base: &HashMap<String, f32>,
    new: Option<&HashMap<String, f32>>,
    scenario_name: String,
    user_count: usize,
    config: &Config,
) -> anyhow::Result<()> {
    if !path.is_dir() {
        return Err(anyhow!("{} is not a valid directory", path.display()));
    }
    goose_stats_writecsv(base, new, path)?;
    tpt_stats_prettyprint(base, new, config);

    if std::env::var("PUSH_METRICS").unwrap_or_default() == "TRUE" {
        let labels = HashMap::from([
            ("url1".to_string(), config.url1.clone().replace('/', "")),
            ("url2".to_string(), config.url2.clone().replace('/', "")),
            ("hash_count".to_string(), config.hash_count.0.to_string()),
            ("users".to_string(), user_count.to_string()),
            ("scenario".to_string(), scenario_name),
        ]);
        println!("Pushing metrics to Prometheus with labels: {:?}", labels);
        send_pushgateway(&config.pushgateway_url, base, labels)?;
    }

    Ok(())
}
