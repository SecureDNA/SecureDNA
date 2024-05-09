// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("while {ctx}: {status_wrap}, {retriable_wrap}: {source}", status_wrap=StatusWrapper(*status), retriable_wrap=RetriableWrapper(*retriable))]
    RequestError {
        ctx: String,
        /// The HTTP status code of the error, or 000 if no status was available.
        status: Option<u16>,
        retriable: bool,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("decoding {decoding}: {source}")]
    DecodeError {
        decoding: String,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("encoding {encoding}: {source}")]
    EncodeError {
        encoding: String,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("protocol error: {error}")]
    ProtocolError { error: String },
    #[error("in js: {error}")]
    JsError { error: String },
}

impl HttpError {
    pub fn is_retriable(&self) -> bool {
        match self {
            HttpError::RequestError { retriable, .. } => *retriable,
            HttpError::DecodeError { .. }
            | HttpError::EncodeError { .. }
            | HttpError::ProtocolError { .. }
            | HttpError::JsError { .. } => false,
        }
    }
}

struct StatusWrapper(Option<u16>);

impl std::fmt::Display for StatusWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            None => f.write_str("no status"),
            Some(status) => write!(f, "status: {status}"),
        }
    }
}

struct RetriableWrapper(bool);

impl std::fmt::Display for RetriableWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            false => f.write_str("not retriable"),
            true => f.write_str("retriable"),
        }
    }
}
