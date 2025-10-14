// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::ServerPrevalidation;

// This exists to work around `clap` wanting the version to be a literal.
#[macro_export]
macro_rules! latest_client_version {
    () => {
        2
    };
}

/// Used to represent the version of the SCEP protocol used to communicate.
///
/// Why not use this to hold server versions too? Because servers must be aware of all SCEP
/// protocol versions any client may use, but current clients may eventually encounter servers
/// that support not-yet-existant SCEP protocol versions. Such versions cannot be represented
/// by this type, so using it to hold server versions would break forward compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientVersion {
    V1,
    V2,
}

impl ClientVersion {
    pub const LATEST: Self = Self::V2;
}

impl TryFrom<u64> for ClientVersion {
    type Error = ServerPrevalidation;

    fn try_from(version: u64) -> Result<Self, Self::Error> {
        match version {
            0 => Err(ServerPrevalidation::ClientVersionTooLow),
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(ServerPrevalidation::ClientVersionTooHigh),
        }
    }
}

impl From<ClientVersion> for u64 {
    fn from(version: ClientVersion) -> u64 {
        match version {
            ClientVersion::V1 => 1,
            ClientVersion::V2 => 2,
        }
    }
}

impl std::fmt::Display for ClientVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        u64::from(*self).fmt(f)
    }
}

impl serde::Serialize for ClientVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u64::from(*self).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ClientVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let version = u64::deserialize(deserializer)?;
        version.try_into().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_versions_match() {
        assert_eq!(latest_client_version!(), u64::from(ClientVersion::LATEST));
    }
}
