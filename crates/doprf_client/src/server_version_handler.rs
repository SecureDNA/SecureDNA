// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::future::Future;
use std::pin::Pin;

use tracing::info;

use crate::error::DoprfError;

type DynFuture<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;
type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;
type DynResult<T> = Result<T, DynError>;

type GetVersion = Box<dyn Fn(String) -> DynFuture<DynResult<Option<u64>>> + Send + Sync>;
type SetVersion = Box<dyn Fn(String, u64) -> DynFuture<DynResult<()>> + Send + Sync>;

/// Server version handlers for downgrade checks.
///
/// `LastServerVersionHandler::default()` implements a null handler, if you don't
/// need to check for downgrades.
pub struct LastServerVersionHandler {
    get_version: GetVersion,
    set_version: SetVersion,
}

impl LastServerVersionHandler {
    pub fn new(get_version: GetVersion, set_version: SetVersion) -> Self {
        Self {
            get_version,
            set_version,
        }
    }

    pub async fn get_server_version(&self, domain: String) -> Result<Option<u64>, DoprfError> {
        (self.get_version)(domain.clone()).await.map_err(|source| {
            DoprfError::GetLastServerVersion {
                source,
                domain: domain.clone(),
            }
        })
    }

    pub async fn set_server_version(&self, domain: String, server_version: u64) {
        if let Err(err) = (self.set_version)(domain.clone(), server_version).await {
            info!("error: setting server version {server_version} for {domain}: {err}",);
        }
    }
}

impl Default for LastServerVersionHandler {
    fn default() -> Self {
        Self::new(
            Box::new(|_| Box::pin(async { Ok(None) })),
            Box::new(|_, _| Box::pin(async { Ok(()) })),
        )
    }
}
