// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating a `HltToken`.
//! A `Certificate` with the `Infrastructure` role is able to sign a `HltTokenRequest` to issue a `HltToken`.
//! `HltToken`s will be used to identify instances of the hazard lookup table.

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    asn::ToASN1DerBytes,
    error::EncodeError,
    impl_boilerplate_for_token, impl_boilerplate_for_token_request,
    impl_boilerplate_for_token_request_version, impl_boilerplate_for_token_version,
    impl_encoding_boilerplate, impl_key_boilerplate_for_token,
    impl_key_boilerplate_for_token_request, impl_key_boilerplate_for_token_request_version,
    key_traits::HasAssociatedKey,
    keypair::{PublicKey, Signature},
    pem::PemTaggable,
    shared_components::common::{
        CompatibleIdentity, ComponentVersionGuard, Signed, VersionedComponent,
    },
    tokens::{TokenData, TokenGroup},
    CertificateChain, Digestible, Expiration, Id, Infrastructure, Issued, KeyAvailable, KeyPair,
    KeyUnavailable, TokenKind,
};

use super::digest::{HltTokenDigest, HltTokenRequestDigest};

#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[rasn(automatic_tags)]
pub(crate) struct HltTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) request_id: Id,
    pub(crate) public_key: PublicKey,
}

impl HltTokenRequest1 {
    pub fn new(public_key: PublicKey) -> Self {
        let guard = ComponentVersionGuard::new();
        let request_id = Id::new_random();
        Self {
            guard,
            request_id,
            public_key,
        }
    }
}

impl VersionedComponent for HltTokenRequest1 {
    const COMPONENT_NAME: &'static str = "HTR";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all HLT token request versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum HltTokenRequestVersion {
    V1(HltTokenRequest1),
}

pub struct HltTokenRequest {
    pub(crate) version: HltTokenRequestVersion,
}

impl HltTokenRequest {
    pub fn v1_token_request(public_key: PublicKey) -> Self {
        let request = HltTokenRequest1::new(public_key);
        let version = HltTokenRequestVersion::V1(request);

        Self::new(version)
    }
}

impl HltTokenRequest {
    pub(crate) fn new(version: HltTokenRequestVersion) -> HltTokenRequest {
        Self { version }
    }
}

impl Digestible for HltTokenRequest {
    type Digest = HltTokenRequestDigest;
}

impl PemTaggable for HltTokenRequest {
    fn tag() -> String {
        "SECUREDNA HLT TOKEN REQUEST".to_string()
    }
}

impl Decode for HltTokenRequest {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version =
            HltTokenRequestVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(HltTokenRequest::new(version))
    }
}

/// Data that will be signed by the issuer of the HLTRequest
#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[rasn(automatic_tags)]
pub(crate) struct HltTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) issuance_id: Id,
    pub(crate) identity: CompatibleIdentity,
    pub(crate) expiration: Expiration,
}

impl HltTokenIssuer1 {
    pub(crate) fn new(identity: CompatibleIdentity, expiration: Expiration) -> Self {
        let guard = ComponentVersionGuard::new();
        let issuance_id = Id::new_random();
        Self {
            guard,
            issuance_id,
            identity,
            expiration,
        }
    }
}

impl VersionedComponent for HltTokenIssuer1 {
    const COMPONENT_NAME: &'static str = "HTI";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all HLT token versions.
#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum HltTokenVersion {
    V1(Signed<TokenData<HltTokenRequest1, HltTokenIssuer1>>),
}

impl HltTokenVersion {
    pub fn public_key(&self) -> &PublicKey {
        match self {
            HltTokenVersion::V1(s) => &s.data.request.public_key,
        }
    }
}

/// Token for identifying instances of the hazard lookup table
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HltToken<K> {
    pub(crate) version: HltTokenVersion,
    key_state: K,
}

impl<K> Digestible for HltToken<K> {
    type Digest = HltTokenDigest;
}

impl<K> PemTaggable for HltToken<K> {
    fn tag() -> String {
        "SECUREDNA HLT TOKEN".to_string()
    }
}

impl HltToken<KeyUnavailable> {
    pub(crate) fn new(version: HltTokenVersion) -> HltToken<KeyUnavailable> {
        Self {
            version,
            key_state: KeyUnavailable,
        }
    }
}

impl Decode for HltToken<KeyUnavailable> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = HltTokenVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(HltToken::new(version))
    }
}
/// Related types for HltToken
#[derive(AsnType, Encode, Decode)]
pub struct HltTokenGroup;

impl TokenGroup for HltTokenGroup {
    type AssociatedRole = Infrastructure;
    type TokenRequest = HltTokenRequest;
    type Token = HltToken<KeyUnavailable>;
    type ChainType = CertificateChain<Self::AssociatedRole>;

    fn token_kind() -> TokenKind {
        TokenKind::Hlt
    }
}

impl_boilerplate_for_token_request_version! {HltTokenRequestVersion, V1}
impl_key_boilerplate_for_token_request_version! {HltTokenRequestVersion, V1}

impl_boilerplate_for_token_request! {HltTokenRequest}
impl_key_boilerplate_for_token_request! {HltTokenRequest}
impl_encoding_boilerplate! {HltTokenRequest}

impl_boilerplate_for_token_version! {HltTokenVersion, V1}
impl_boilerplate_for_token! {HltToken<K>}
impl_encoding_boilerplate! {HltToken<K>}
impl_key_boilerplate_for_token! {HltToken}

#[cfg(test)]
mod test {

    use crate::key_traits::{CanLoadKey, HasAssociatedKey, KeyLoaded};
    use crate::{
        asn::{FromASN1DerBytes, ToASN1DerBytes},
        test_helpers::create_leaf_cert,
        DatabaseTokenRequest, Expiration, HltTokenRequest, Infrastructure, KeyPair,
    };

    #[test]
    fn can_issue_hlt_token() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = HltTokenRequest::v1_token_request(kp.public_key());

        cert.issue_hlt_token(req, Expiration::default()).unwrap();
    }

    #[test]
    fn cannot_decode_hlt_token_request_as_db_token_request() {
        let kp = KeyPair::new_random();
        let token_req = HltTokenRequest::v1_token_request(kp.public_key());
        let encoded = token_req.to_der().unwrap();
        let res = DatabaseTokenRequest::from_der(encoded);
        assert!(res.is_err())
    }

    #[test]
    fn hlt_token_has_expected_public_key() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = HltTokenRequest::v1_token_request(kp.public_key());

        let token = cert.issue_hlt_token(req, Expiration::default()).unwrap();

        assert_eq!(&kp.public_key(), token.public_key());
    }

    #[test]
    fn hlt_token_can_sign_with_associated_keypair() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = HltTokenRequest::v1_token_request(kp.public_key());

        let token = cert
            .issue_hlt_token(req, Expiration::default())
            .unwrap()
            .load_key(kp)
            .unwrap();

        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }
}
