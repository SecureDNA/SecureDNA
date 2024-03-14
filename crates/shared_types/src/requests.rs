// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
use std::str::FromStr;

use uuid::Uuid;

/// A unique per-request ID that is passed to us (generally from synthclient),
/// and we pass unchanged through to the keyservers and hdb as an HTTP header.
/// This helps with tracing the path of a request through the logs of the
/// various different servers.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

impl FromStr for RequestId {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(String::from(s)))
    }
}

impl RequestId {
    pub const FIELD: &'static str = "X-Request-ID";

    pub fn new_unique() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn new_unique_with_prefix(prefix: &str) -> Self {
        Self(format!("{prefix}-{}", Uuid::new_v4()))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, std::str::Utf8Error> {
        let s = std::str::from_utf8(b)?;
        Ok(Self(String::from(s)))
    }

    pub fn unknown() -> Self {
        Self("unknown".into())
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A "context" object indicating which part of which request is being handled.
/// Used for logging and UI progress reports.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// The ID of the whole synthesis request.
    pub id: RequestId,

    /// If the synthesis request was a FASTA file consisting of multiple
    /// records, this is total number of records in the file.
    pub total_records: usize,
}

impl RequestContext {
    pub fn single(id: RequestId) -> RequestContext {
        RequestContext {
            id,
            total_records: 1,
        }
    }
}

impl fmt::Display for RequestContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.total_records > 1 {
            write!(f, "{} ({} records)", &self.id, self.total_records)
        } else {
            write!(f, "{}", &self.id)
        }
    }
}
