// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;
use std::sync::Arc;

use hyper::StatusCode;
use shared_types::server_versions::HdbVersion;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use certificates::{DatabaseTokenGroup, KeyAvailable, PublicKey, VerifierToken};
use hdb::{Database, HazardLookupTable};
use hdb_api::verification::Verifier;
use minhttp::response::{self, GenericResponse};
use scep_server_helpers::server::ServerState;
use shared_types::hash::HashSpec;
use shared_types::metrics::HdbMetrics;

use crate::event_store::Connection;
use crate::mail::MailService;
use crate::validation::NetworkingValidator;

pub struct HdbServerState {
    pub version: HdbVersion,
    pub database_path: PathBuf,
    pub database: Arc<Database>,
    pub heavy_requests: Arc<Semaphore>,
    pub hlt: Arc<HazardLookupTable>,
    pub metrics: Option<Arc<HdbMetrics>>,
    pub hdb_queries: Arc<Semaphore>,
    pub parallelism_per_request: usize,
    pub hash_spec: HashSpec,
    #[allow(dead_code)]
    pub validator: NetworkingValidator,
    pub scep: ServerState<DatabaseTokenGroup>,
    pub et_size_limit: u64,
    pub exemptions_roots: Vec<PublicKey>,
    pub persistence_path: PathBuf,
    pub persistence_connection: Connection,
    /// Used to sign responses for verifiable screening
    /// Uses a different token than the one used for SCEP
    pub verifier: Option<Verifier<VerifierToken<KeyAvailable>>>,
    pub mail_service: Option<MailService>,
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
