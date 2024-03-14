// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum HTTPError {
    #[error("while {ctx}, retriable {retriable}: {source}")]
    RequestError {
        ctx: String,
        retriable: bool,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("decoding {decoding}: {source}")]
    DecodeError {
        decoding: String,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("in js: {error}")]
    JsError { error: String },
}

impl HTTPError {
    pub fn is_retriable(&self) -> bool {
        match self {
            HTTPError::RequestError { retriable, .. } => *retriable,
            HTTPError::DecodeError { .. } | HTTPError::JsError { .. } => false,
        }
    }
}
