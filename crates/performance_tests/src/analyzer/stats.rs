// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

/* Single suite analysis functions */

use crate::shared::types::HashCount;
use goose::metrics::GooseMetrics;
use std::collections::HashMap;

pub fn calc_goose(metrics: &GooseMetrics, hash_count: HashCount) -> HashMap<String, f32> {
    // This function is a copy of the internal Goose metrics calculation in
    // https://github.com/tag1consulting/goose/blob/0.17.0/src/metrics.rs#L1260
    // Any changes to this code should be compatible with Goose internals

    // This code can't handle scenarios/transactions with multiple requests
    assert_eq!(metrics.requests.len(), 1);

    let (_request_key, request) = metrics.requests.iter().next().unwrap();

    let failure_rate = match request.fail_count {
        0 => 0.0,
        _ => {
            100.0 * request.fail_count as f32 / (request.success_count + request.fail_count) as f32
        }
    };

    let raw_average = match request.raw_data.counter {
        0 => 0.0,
        _ => request.raw_data.total_time as f32 / request.raw_data.counter as f32,
    };

    let median = goose::util::median(
        &request.raw_data.times,
        request.raw_data.counter,
        request.raw_data.minimum_time,
        request.raw_data.maximum_time,
    ) as f32;

    let min = request.raw_data.minimum_time as f32;
    let max = request.raw_data.maximum_time as f32;

    let num_users = metrics.total_users;

    let hash_rate = 1000.0 / raw_average * num_users as f32 * hash_count.0 as f32;
    let bp_rate = 1000.0 / raw_average * num_users as f32 * hash_count.to_bp_count().0 as f32;

    HashMap::from([
        (String::from("bp_s"), bp_rate),
        (String::from("hash_s"), hash_rate),
        (String::from("min_ms"), min),
        (String::from("max_ms"), max),
        (String::from("spread"), max - min),
        (String::from("mean_ms"), raw_average),
        (String::from("median_ms"), median),
        (String::from("fail_rt"), failure_rate),
    ])
}
