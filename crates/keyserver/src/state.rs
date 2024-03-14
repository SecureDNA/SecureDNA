// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use hyper::StatusCode;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use certificates::KeyserverTokenGroup;
use doprf::party::KeyserverId;
use doprf::prf::KeyShare;
use minhttp::response::{self, GenericResponse};
use scep_server_helpers::server::ServerState;
use shared_types::metrics::KSMetrics;
use shared_types::server_selection::KeyInfo;

/// Holds the keyserver's constant (for now) information about what generations it supports,
/// and what the thresholds are for that generation
#[derive(Clone)]
pub struct GenerationKeyInfo(pub HashMap<u32, KeyInfo>);

pub struct KeyserverState {
    pub heavy_requests: Arc<Semaphore>,
    pub keyserver_id: KeyserverId,
    pub keyshare: KeyShare,
    pub generations_key_info: GenerationKeyInfo,
    pub metrics: Option<Arc<KSMetrics>>,
    pub processing_chunks: Arc<Semaphore>,
    pub parallelism_per_request: usize,
    pub scep: ServerState<KeyserverTokenGroup>,
}

impl KeyserverState {
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
