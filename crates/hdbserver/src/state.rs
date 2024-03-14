// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use hyper::StatusCode;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use certificates::DatabaseTokenGroup;
use hdb::{self, Database, HazardLookupTable};
use minhttp::response::{self, GenericResponse};
use scep_server_helpers::server::ServerState;
use shared_types::hash::HashSpec;
use shared_types::metrics::HDBMetrics;

use crate::event_store::Connection;
use crate::validation::NetworkingValidator;

#[derive(Clone)]
pub struct BuildTimestamp(pub String);

pub struct HdbServerState {
    pub build_timestamp: Option<BuildTimestamp>,
    pub database: Database,
    pub heavy_requests: Arc<Semaphore>,
    pub hlt: HazardLookupTable,
    pub metrics: Option<Arc<HDBMetrics>>,
    pub hdb_queries: Arc<Semaphore>,
    pub parallelism_per_request: usize,
    pub hash_spec: HashSpec,
    #[allow(dead_code)]
    pub validator: NetworkingValidator,
    pub scep: ServerState<DatabaseTokenGroup>,
    pub persistence_connection: Connection,
}

impl HdbServerState {
    pub fn throttle_heavy_requests(&self) -> Result<OwnedSemaphorePermit, GenericResponse> {
        self.heavy_requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                response::text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Server is overloaded. Try again later.",
                )
            })
    }
}
