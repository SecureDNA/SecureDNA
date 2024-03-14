// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating an `ExemptionListTokenRequest`.
//! A `Certificate` is able to sign a `ExemptionListTokenRequest` to issue a `ExemptionListToken`.

use std::fmt::Display;

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    asn::ToASN1DerBytes,
    error::EncodeError,
    impl_boilerplate_for_token, impl_boilerplate_for_token_request,
    impl_boilerplate_for_token_request_version, impl_boilerplate_for_token_version,
    impl_encoding_boilerplate,
    issued::Issued,
    keypair::{PublicKey, Signature},
    pem::PemTaggable,
    shared_components::{
        common::{
            CompatibleIdentity, ComponentVersionGuard, Description, Expiration, Id, Signed,
            VersionedComponent,
        },
        role::Exemption,
    },
    tokens::{TokenData, TokenGroup},
    Formattable,
};

use super::{authenticator::Authenticator, organism::Organism};

// tsgen
type ShippingAddress = Vec<String>;

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
// tsgen
#[rasn(automatic_tags)]
pub(crate) struct ExemptionListTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    /// unique for each token
    request_id: Id,
    exemptions: Vec<Organism>,
    requestor: Description,
    requestor_auth_devices: Vec<Authenticator>,
    shipping_addresses: Vec<ShippingAddress>,
}

impl ExemptionListTokenRequest1 {
    fn new(
        exemptions: Vec<Organism>,
        requestor: Description,
        requestor_auth_devices: Vec<Authenticator>,
        shipping_addresses: Vec<ShippingAddress>,
    ) -> Self {
        let guard = ComponentVersionGuard::new();
        let request_id = Id::new_random();
        Self {
            guard,
            request_id,
            exemptions,
            requestor,
            requestor_auth_devices,
            shipping_addresses,
        }
    }
}
impl VersionedComponent for ExemptionListTokenRequest1 {
    const COMPONENT_NAME: &'static str = "ELTR";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all ELTR versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// tsgen
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum ExemptionListTokenRequestVersion {
    V1(ExemptionListTokenRequest1),
}

#[derive(Debug, PartialEq, Eq)]
// tsgen
pub struct ExemptionListTokenRequest {
    pub(crate) version: ExemptionListTokenRequestVersion,
}

impl ExemptionListTokenRequest {
    pub(crate) fn new(version: ExemptionListTokenRequestVersion) -> Self {
        Self { version }
    }
}

impl ExemptionListTokenRequest {
    pub fn v1_token_request(
        exemptions: Vec<Organism>,
        requestor: Description,
        requestor_auth_devices: Vec<Authenticator>,
        shipping_addresses: Vec<ShippingAddress>,
    ) -> Self {
        let request = ExemptionListTokenRequest1::new(
            exemptions,
            requestor,
            requestor_auth_devices,
            shipping_addresses,
        );
        let version = ExemptionListTokenRequestVersion::V1(request);
        ExemptionListTokenRequest::new(version)
    }
}

impl PemTaggable for ExemptionListTokenRequest {
    fn tag() -> String {
        "SECUREDNA EXEMPTION LIST TOKEN REQUEST".to_string()
    }
}

impl Decode for ExemptionListTokenRequest {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = ExemptionListTokenRequestVersion::decode_with_tag_and_constraints(
            decoder,
            tag,
            constraints,
        )?;
        Ok(ExemptionListTokenRequest::new(version))
    }
}

/// Data that will be signed by the issuer of the ELT
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
// tsgen
#[rasn(automatic_tags)]
pub(crate) struct ExemptionListTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    issuance_id: Id,
    identity: CompatibleIdentity,
    expiration: Expiration,
    issuer_auth_devices: Vec<Authenticator>,
    emails_to_notify: Vec<String>,
}

impl ExemptionListTokenIssuer1 {
    pub(crate) fn new(
        identity: CompatibleIdentity,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
        emails_to_notify: Vec<String>,
    ) -> Self {
        let guard = ComponentVersionGuard::new();
        let issuance_id = Id::new_random();
        Self {
            guard,
            issuance_id,
            identity,
            expiration,
            issuer_auth_devices,
            emails_to_notify,
        }
    }
}

impl VersionedComponent for ExemptionListTokenIssuer1 {
    const COMPONENT_NAME: &'static str = "ELTI";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all ELT versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
// tsgen
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum ExemptionListTokenVersion {
    V1(Signed<TokenData<ExemptionListTokenRequest1, ExemptionListTokenIssuer1>>),
}

impl ExemptionListTokenVersion {
    pub(crate) fn requestor_auth_devices(&self) -> &[Authenticator] {
        match self {
            Self::V1(c) => &c.data.request.requestor_auth_devices,
        }
    }

    pub(crate) fn issuer_auth_devices(&self) -> &[Authenticator] {
        match self {
            Self::V1(c) => &c.data.issuer_fields.issuer_auth_devices,
        }
    }

    pub(crate) fn exemptions(&self) -> &[Organism] {
        match self {
            Self::V1(c) => &c.data.request.exemptions,
        }
    }
}

/// Token to allow the synthesis of restricted hazards
#[derive(Debug, Clone, PartialEq, Eq)]
// tsgen
pub struct ExemptionListToken {
    pub(crate) version: ExemptionListTokenVersion,
}

impl ExemptionListToken {
    pub(crate) fn new(version: ExemptionListTokenVersion) -> Self {
        Self { version }
    }

    pub fn requestor_auth_devices(&self) -> &[Authenticator] {
        self.version.requestor_auth_devices()
    }

    pub fn issuer_auth_devices(&self) -> &[Authenticator] {
        self.version.issuer_auth_devices()
    }

    pub fn exemptions(&self) -> &[Organism] {
        self.version.exemptions()
    }
}

impl PemTaggable for ExemptionListToken {
    fn tag() -> String {
        "SECUREDNA EXEMPTION LIST TOKEN".to_string()
    }
}

impl Decode for ExemptionListToken {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version =
            ExemptionListTokenVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(ExemptionListToken::new(version))
    }
}

/// Related types for ExemptionListToken
#[derive(AsnType, Encode, Decode, Debug)]
pub struct ExemptionListTokenGroup;

impl TokenGroup for ExemptionListTokenGroup {
    type AssociatedRole = Exemption;
    type TokenRequest = ExemptionListTokenRequest;
    type Token = ExemptionListToken;
}

impl_boilerplate_for_token_request_version! {ExemptionListTokenRequestVersion, V1}
impl_boilerplate_for_token_request! {ExemptionListTokenRequest}
impl_encoding_boilerplate! {ExemptionListTokenRequest}

impl_boilerplate_for_token_version! {ExemptionListTokenVersion, V1}
impl_boilerplate_for_token! {ExemptionListToken}
impl_encoding_boilerplate! {ExemptionListToken}

#[derive(Serialize)]
pub struct ExemptionListTokenRequestDigest {
    request_id: Id,
    exemptions: Vec<Organism>,
    requestor: Description,
    requestor_auth_devices: Vec<Authenticator>,
    shipping_addresses: Vec<ShippingAddress>,
}

impl Formattable for ExemptionListTokenRequest {
    type Digest = ExemptionListTokenRequestDigest;
}

impl From<ExemptionListTokenRequest> for ExemptionListTokenRequestDigest {
    fn from(value: ExemptionListTokenRequest) -> Self {
        match value.version {
            ExemptionListTokenRequestVersion::V1(r) => {
                let request_id = r.request_id;
                let exemptions = r.exemptions;
                let requestor = r.requestor;
                let requestor_auth_devices = r.requestor_auth_devices;
                let shipping_addresses = r.shipping_addresses;
                ExemptionListTokenRequestDigest {
                    request_id,
                    exemptions,
                    requestor,
                    requestor_auth_devices,
                    shipping_addresses,
                }
            }
        }
    }
}

impl Display for ExemptionListTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Plaintext display for this token has not yet been implemented"
        )
    }
}

#[derive(Serialize)]
pub struct ExemptionListTokenDigest {
    request_id: Id,
    requestor: Description,
    requestor_auth_devices: Vec<Authenticator>,
    shipping_addresses: Vec<ShippingAddress>,
    issuance_id: Id,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    issuer_auth_devices: Vec<Authenticator>,
    emails_to_notify: Vec<String>,
    signature: Signature,
    signature_verifies: bool,
}

impl Formattable for ExemptionListToken {
    type Digest = ExemptionListTokenDigest;
}

impl From<ExemptionListToken> for ExemptionListTokenDigest {
    fn from(value: ExemptionListToken) -> Self {
        let signature_verifies = value.signature_verifies();
        match value.version {
            ExemptionListTokenVersion::V1(t) => {
                let request_id = t.data.request.request_id;
                let requestor = t.data.request.requestor;
                let requestor_auth_devices = t.data.request.requestor_auth_devices;
                let shipping_addresses = t.data.request.shipping_addresses;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let issued_by = t.data.issuer_fields.identity;
                let expiration = t.data.issuer_fields.expiration;
                let issuer_auth_devices = t.data.issuer_fields.issuer_auth_devices;
                let emails_to_notify = t.data.issuer_fields.emails_to_notify;
                let signature = t.signature;

                ExemptionListTokenDigest {
                    request_id,
                    requestor,
                    requestor_auth_devices,
                    shipping_addresses,
                    issuance_id,
                    issued_by,
                    expiration,
                    issuer_auth_devices,
                    emails_to_notify,
                    signature,
                    signature_verifies,
                }
            }
        }
    }
}

impl Display for ExemptionListTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Plaintext display for this token has not yet been implemented"
        )
    }
}

#[cfg(test)]
mod test {
    use crate::{
        test_helpers::{create_eltr, create_leaf_cert},
        Exemption, ExemptionListToken, ExemptionListTokenRequest, Expiration, PemDecodable,
        PemEncodable,
    };

    #[test]
    fn can_issue_exemption_token() {
        let cert = create_leaf_cert::<Exemption>();
        let request = create_eltr();
        cert.issue_elt(request, Expiration::default(), vec![])
            .unwrap();
    }

    #[test]
    fn can_serialise_eltr_to_pem() {
        let eltr = create_eltr();
        let encoded = eltr.to_pem().unwrap();
        let eltr_decoded = ExemptionListTokenRequest::from_pem(encoded).unwrap();
        assert_eq!(eltr, eltr_decoded);
    }

    #[test]
    fn can_serialise_elt_to_pem() {
        let leaf_cert = create_leaf_cert::<Exemption>();
        let eltr = create_eltr();

        let issuer_auth_devices = Vec::new();

        let elt = leaf_cert
            .issue_elt(
                eltr,
                Expiration::expiring_in_days(90).unwrap(),
                issuer_auth_devices,
            )
            .unwrap();

        let encoded = elt.to_pem().unwrap();
        let elt_decoded = ExemptionListToken::from_pem(encoded).unwrap();

        assert_eq!(elt, elt_decoded);
    }
}
