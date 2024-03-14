// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use prometheus::core::{AtomicI64, GenericGauge};
use prometheus::{self, IntCounter, IntGauge};
use prometheus::{register_int_counter, register_int_gauge, Encoder, TextEncoder};

static HASH_COUNTER_NAME: &str = "total_hashes_processed";
static HASH_COUNTER_DESCRIPTION: &str = "Total number of 32B hashes processed since last start";

static BP_COUNTER_NAME: &str = "total_bps_processed";
static BP_COUNTER_DESCRIPTION: &str = "Total number of base pairs processed since last start";

static CONNECTED_CLIENTS_NAME: &str = "currently_processing_client_requests";
static CONNECTED_CLIENTS_DESCRIPTION: &str =
    "Current number of client requests that are being processed";

static MAX_CLIENTS_NAME: &str = "maximum_processing_clients";
static MAX_CLIENTS_DESCRIPTION: &str =
    "Maximum number of client requests that can be processed concurrently";

static TOTAL_REQUESTS_NAME: &str = "total_requests";
static TOTAL_REQUESTS_DESCRIPTION: &str = "Total number of requests processed since last start";

static TOTAL_HAZARDS_NAME: &str = "total_hazards_hits";
static TOTAL_HAZARDS_DESCRIPTION: &str = "Total number of hazard hits since last start";

static BAD_REQUESTS_NAME: &str = "bad_requests";
static BAD_REQUESTS_DESCRIPTION: &str =
    "Total number of rejected / malformed requests since last start";

static HDB_IO_ERRORS_NAME: &str = "hdb_io_errors";
static HDB_IO_ERRORS_DESCRIPTION: &str =
    "Total number of I/O errors (disk read errors, malformed entries, etc.) since last start";

pub struct SynthClientMetrics {
    pub hash_counter: IntCounter,
    pub bp_counter: IntCounter,
    connected_clients: IntGauge,
    pub max_clients: IntGauge,
    pub requests: IntCounter,
    pub hazards: IntCounter,
}

impl SynthClientMetrics {
    pub fn new() -> SynthClientMetrics {
        SynthClientMetrics {
            hash_counter: register_int_counter!(HASH_COUNTER_NAME, HASH_COUNTER_DESCRIPTION,)
                .unwrap(),
            bp_counter: register_int_counter!(BP_COUNTER_NAME, BP_COUNTER_DESCRIPTION,).unwrap(),
            connected_clients: register_int_gauge!(
                CONNECTED_CLIENTS_NAME,
                CONNECTED_CLIENTS_DESCRIPTION
            )
            .unwrap(),
            max_clients: register_int_gauge!(MAX_CLIENTS_NAME, MAX_CLIENTS_DESCRIPTION,).unwrap(),
            requests: register_int_counter!(TOTAL_REQUESTS_NAME, TOTAL_REQUESTS_DESCRIPTION)
                .unwrap(),
            hazards: register_int_counter!(TOTAL_HAZARDS_NAME, TOTAL_HAZARDS_DESCRIPTION).unwrap(),
        }
    }

    /// Returns a Gauge tracing the number of connected clients
    /// which automatically increments when created
    /// and automatically decrements when the object goes out of scope
    pub fn connected_clients(&self) -> RAIIGauge {
        RAIIGauge::new(&self.connected_clients)
    }
}

impl Default for SynthClientMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HDBMetrics {
    pub hash_counter: IntCounter,
    connected_clients: IntGauge,
    pub max_clients: IntGauge,
    pub requests: IntCounter,
    pub io_errors: IntCounter,
    pub bad_requests: IntCounter,
}

impl HDBMetrics {
    pub fn new() -> HDBMetrics {
        HDBMetrics {
            hash_counter: register_int_counter!(HASH_COUNTER_NAME, HASH_COUNTER_DESCRIPTION,)
                .unwrap(),
            connected_clients: register_int_gauge!(
                CONNECTED_CLIENTS_NAME,
                CONNECTED_CLIENTS_DESCRIPTION
            )
            .unwrap(),
            max_clients: register_int_gauge!(MAX_CLIENTS_NAME, MAX_CLIENTS_DESCRIPTION,).unwrap(),
            requests: register_int_counter!(TOTAL_REQUESTS_NAME, TOTAL_REQUESTS_DESCRIPTION)
                .unwrap(),
            io_errors: register_int_counter!(HDB_IO_ERRORS_NAME, HDB_IO_ERRORS_DESCRIPTION)
                .unwrap(),
            bad_requests: register_int_counter!(BAD_REQUESTS_NAME, BAD_REQUESTS_DESCRIPTION)
                .unwrap(),
        }
    }

    /// Returns a Gauge tracing the number of connected clients
    /// which automatically increments when created
    /// and automatically decrements when the object goes out of scope
    pub fn connected_clients(&self) -> RAIIGauge {
        RAIIGauge::new(&self.connected_clients)
    }
}

impl Default for HDBMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct KSMetrics {
    pub hash_counter: IntCounter,
    connected_clients: IntGauge,
    pub max_clients: IntGauge,
    pub requests: IntCounter,
    pub bad_requests: IntCounter,
}

impl KSMetrics {
    pub fn new() -> KSMetrics {
        KSMetrics {
            hash_counter: register_int_counter!(HASH_COUNTER_NAME, HASH_COUNTER_DESCRIPTION,)
                .unwrap(),
            connected_clients: register_int_gauge!(
                CONNECTED_CLIENTS_NAME,
                CONNECTED_CLIENTS_DESCRIPTION
            )
            .unwrap(),
            max_clients: register_int_gauge!(MAX_CLIENTS_NAME, MAX_CLIENTS_DESCRIPTION,).unwrap(),
            requests: register_int_counter!(TOTAL_REQUESTS_NAME, TOTAL_REQUESTS_DESCRIPTION)
                .unwrap(),
            bad_requests: register_int_counter!(BAD_REQUESTS_NAME, BAD_REQUESTS_DESCRIPTION)
                .unwrap(),
        }
    }

    /// Returns a Gauge tracing the number of connected clients
    /// which automatically increments when created
    /// and automatically decrements when the object goes out of scope
    pub fn connected_clients(&self) -> RAIIGauge {
        RAIIGauge::new(&self.connected_clients)
    }
}

impl Default for KSMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements a RAII box for Prometheus Gauges
/// Handle incrementing/decrementing automatically based on scope
pub struct RAIIGauge {
    metric: GenericGauge<AtomicI64>,
}

impl RAIIGauge {
    pub fn new(gauge: &GenericGauge<AtomicI64>) -> RAIIGauge {
        let gauge = RAIIGauge {
            metric: gauge.clone(),
        };
        gauge.metric.inc();
        gauge
    }
}

impl Drop for RAIIGauge {
    fn drop(&mut self) {
        self.metric.dec();
    }
}

/// Generates a simple TEXT representation of all existing metrics
pub fn get_metrics_output() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();

    let metric_families = prometheus::gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer.clone()).unwrap()
}
