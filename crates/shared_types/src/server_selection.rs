// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{collections::HashMap, fmt, str::FromStr};

use doprf::{active_security::ActiveSecurityKey, party::KeyserverId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// tsgen
pub enum Tier {
    #[serde(rename = "staging")]
    Staging,
    #[serde(rename = "prod")]
    Prod,
    #[serde(rename = "dev")]
    Dev,
}

impl Tier {
    /// Get the string used in the domain name of a server with this tier
    /// e.g., for a `Tier::Dev` keyserver, this returns the `dev` of `1.ks.dev.securedna.org`
    pub fn domain_str(&self) -> &'static str {
        match self {
            Tier::Staging => "staging",
            Tier::Prod => "prod",
            Tier::Dev => "dev",
        }
    }
}

impl FromStr for Tier {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "staging" => Ok(Self::Staging),
            "prod" => Ok(Self::Prod),
            "dev" => Ok(Self::Dev),
            _ => Err("not a valid tier"),
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.domain_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Keyserver,
    Hdb,
}

impl Role {
    /// Get the string used in the domain name of a server with this role
    /// e.g., for a `Role::Keyserver` server, this returns the `ks` of `1.ks.dev.securedna.org`
    pub fn domain_str(&self) -> &'static str {
        match self {
            Role::Keyserver => "ks",
            Role::Hdb => "db",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualificationRequest {
    /// The protocol version this client wants to use, so servers can reject out-of-date clients
    /// or adjust behavior
    pub client_version: u32,
    // TODO: client cert chain
}

/// Details on the key that forms the basis of the distributed keyshares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Equal to the number of keyholders required
    pub quorum: u32,
    /// Used to verify the keyserver's screening response
    pub active_security_key: ActiveSecurityKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyserverQualificationResponse {
    /// This *typically* matches the domain name, but might not in case of failures / spares / replicas,
    /// so this should be treated as the source of truth, not the domain name
    pub id: KeyserverId,
    /// Keyed by which generation numbers this keyserver supports, with values for the quorum (N of N-of-M)
    /// and active security key required for that generation according to this keyserver.
    pub generations_and_key_info: HashMap<u32, KeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HdbQualificationResponse {
    /// Which generation numbers this HDB supports (usually one, but sometimes more)
    pub supported_generations: Vec<u32>,
}
