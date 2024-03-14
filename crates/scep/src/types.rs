// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use shared_types::{hash::HashSpec, synthesis_permission::Region};

use doprf::party::KeyserverIdSet;

pub use crate::nonce::{ClientNonce, ServerNonce};
use certificates::{
    DatabaseTokenGroup, Id, Issued, KeyserverTokenGroup, Signature, SynthesizerTokenGroup,
    TokenBundle, TokenGroup,
};

/// The initial client request that begins prevalidation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenRequest {
    /// V_c, the (non-negotiated) protocol version.
    /// Do not change this field name, it is hardcoded in steps.rs for the
    /// pre-deserialization version check.
    pub protocol_version: u64,
    /// A freeform version hint so the servers can track client distribution.
    pub version_hint: String,
    pub nonce: ClientNonce,
    pub request_type: ClientRequestType,
    #[serde(with = "cert_chain_serde")]
    pub cert_chain: TokenBundle<SynthesizerTokenGroup>,
    pub nucleotide_total_count: u64,
    #[serde(with = "keyserver_id_set_serde")]
    pub keyserver_id_set: KeyserverIdSet,
}

impl OpenRequest {
    /// Unique id from client machine certificate
    pub fn client_mid(&self) -> Id {
        *self.cert_chain.token.issuance_id()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenCommon {
    /// The region to use when determining whether to deny a hazard.
    pub region: Region,
    /// An arbitrary string provided by the provider which is echoed back in the response.
    /// (This allows for a signed response to be recognized as genuinely
    /// corresponding to the request.)
    pub provider_reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "endpoint")]
pub enum ClientRequestType {
    #[serde(rename = "keyserve")]
    Keyserve,
    #[serde(rename = "screen")]
    Screen(ScreenCommon),
    #[serde(rename = "screen-with-EL")]
    ScreenWithEL {
        #[serde(flatten)]
        common: ScreenCommon,
        /// A 2FA one-time password that unlocks this request's exemption list tokens.
        otp: String,
    },
    #[serde(rename = "report-AS-failure")]
    ReportASFailure,
}

/// The server response to an `OpenRequest` during mutual authentication.
///
/// This struct is generic over the token kind of the server response
/// (e.g., is this response from a keyserver or an hdbserver?)
/// See the type aliases `KeyserverOpenResponse` and `HdbserverOpenResponse`.
#[derive(Serialize, Deserialize)]
pub struct OpenResponse<TokenKind: TokenGroup> {
    /// The non-negotiated server version, V_s.
    /// Do not change this field name, it is hardcoded in steps.rs for the
    /// pre-deserialization version check.
    pub server_version: u64,
    pub nonce: ServerNonce,
    #[serde(with = "cert_chain_serde")]
    pub cert_chain: TokenBundle<TokenKind>,
    pub sig: Signature,
    pub hash_spec: HashSpec,
}

pub type KeyserverOpenResponse = OpenResponse<KeyserverTokenGroup>;
pub type HdbserverOpenResponse = OpenResponse<DatabaseTokenGroup>;

/// The client request back to the server after verifying the server's mutual authentication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticateRequest {
    pub sig: Signature,
    pub hash_total_count: u64,
}

mod cert_chain_serde {
    //! DER + Base64 ser/de helpers for certificate chains

    use std::borrow::Cow;

    use serde::{Deserialize, Deserializer, Serializer};

    use crate::base64;
    use certificates::{TokenBundle, TokenGroup};

    pub fn serialize<S, T>(cert_chain: &TokenBundle<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: TokenGroup,
    {
        let b64der = base64::encode(cert_chain.to_wire_format().map_err(|e| {
            serde::ser::Error::custom(format_args!("serializing certificate to wire format: {e}"))
        })?);
        serializer.serialize_str(&b64der)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<TokenBundle<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: TokenGroup,
    {
        // serde may need to allocate in some scenarios (TODO: not sure which exactly)
        let s: Cow<'de, str> = Cow::<'de, str>::deserialize(deserializer)?;
        let der = base64::decode(&s).map_err(serde::de::Error::custom)?;
        <TokenBundle<T>>::from_wire_format(der).map_err(serde::de::Error::custom)
    }
}

mod keyserver_id_set_serde {
    use super::*;

    use serde::{Deserialize, Deserializer, Serializer};

    use doprf::party::KeyserverId;

    /// Serialize a KeyserverIdSet as a bare array [1, 2, 3]
    pub fn serialize<S>(keyserver_id_set: &KeyserverIdSet, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(keyserver_id_set.iter())
    }

    /// Deserialize a KeyserverIdSet from a bare array [1, 2, 3]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyserverIdSet, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ids = Vec::<KeyserverId>::deserialize(deserializer)?;
        Ok(ids.into())
    }
}
