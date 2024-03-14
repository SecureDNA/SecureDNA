// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use prometheus::core::Collector;
use prometheus::Gauge;
use std::collections::HashMap;

pub fn send_pushgateway(
    address: &str,
    testmetrics: &HashMap<String, f32>,
    labels: HashMap<String, String>,
) -> anyhow::Result<()> {
    let help = "Goose Benchmark Metric";

    let mut metrics = vec![];

    for (key, value) in testmetrics {
        let gauge = Gauge::new(key, help)?;
        gauge.set(*value as f64);
        metrics.extend(gauge.collect());
    }

    prometheus::push_metrics("goose_perftest_framework", labels, address, metrics, None)?;

    Ok(())
}
