// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::Duration;

use thiserror::Error;

use crate::{server_selection::ServerSelectionError, windows::WindowsError};
use doprf::prf::{DecodeError, QueryError};

#[derive(Debug, Error)]
pub enum DoprfError {
    #[error("Timed out after {:.3}s", after.as_secs_f64())]
    Timeout { after: Duration },
    #[error("Error during server selection: {0}")]
    ServerSelectionError(#[from] ServerSelectionError),
    #[error("Error querying last server version for {domain}: {source}")]
    GetLastServerVersion {
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        domain: String,
    },
    #[error("Error during HTTP: {0}")]
    HttpError(#[from] http_client::HttpError),
    #[error("Error during SCEP for {domain}: {source}")]
    ScepError {
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        domain: String,
    },
    #[error("Order exceeds maximum size")]
    SequencesTooBig,
    #[error("Error windowing the provided sequences: {0}")]
    WindowsError(#[from] WindowsError),
    #[error("Error while decoding ristretto points: {0}")]
    DecodeError(#[from] DecodeError),
    #[error("Error incorporating queries: {0}")]
    CryptoError(#[from] QueryError),
    #[error("Hazard database responded with invalid record number. This is a bug.")]
    InvalidRecord,
}

impl DoprfError {
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::Timeout { .. } => true,
            Self::ServerSelectionError(_) => true,
            Self::GetLastServerVersion { .. } => false,
            Self::HttpError(e) => e.is_retriable(),
            Self::ScepError { .. } => false,
            Self::SequencesTooBig => false,
            Self::WindowsError { .. } => false,
            Self::DecodeError { .. } => false,
            Self::CryptoError { .. } => false,
            Self::InvalidRecord => false,
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<scep_client_helpers::Error<E>>
    for DoprfError
{
    fn from(value: scep_client_helpers::Error<E>) -> Self {
        match value {
            scep_client_helpers::Error::Http(e) => e.into(),
            scep_client_helpers::Error::Scep { source, domain } => DoprfError::ScepError {
                source: Box::new(source),
                domain,
            },
        }
    }
}
