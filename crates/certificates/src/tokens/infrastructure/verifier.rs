// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating `VerifierTokenRequest` and `VerifierToken`.
//! A `Certificate` with the `Infrastructure` role is able to sign a `VerifierTokenRequest` to issue a `VerifierToken`.
//! A `VerifierToken` identifier a "verifier": the part of the HDB that performs verifiable screening.

use rasn::{Decode, Encode, types::*};
use serde::{Deserialize, Serialize};

use crate::{
    CertificateChain, Digestible, Infrastructure, KeyAvailable, KeyUnavailable, SigningKeyPair,
    TokenKind,
    asn::ToASN1DerBytes,
    error::EncodeError,
    impl_boilerplate_for_token, impl_boilerplate_for_token_request,
    impl_boilerplate_for_token_request_version, impl_boilerplate_for_token_version,
    impl_encoding_boilerplate, impl_key_boilerplate_for_token,
    impl_key_boilerplate_for_token_request, impl_key_boilerplate_for_token_request_version,
    issued::Issued,
    key::signing::{PublicKey, Signature},
    key_traits::HasAssociatedSigningKey,
    pem::PemTaggable,
    shared_components::common::{
        CompatibleIdentity, ComponentVersionGuard, Expiration, Id, Signed, VersionedComponent,
    },
    tokens::{TokenData, TokenGroup},
};

use super::digest::{VerifierTokenDigest, VerifierTokenRequestDigest};

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
pub(crate) struct VerifierTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) request_id: Id,
    pub(crate) public_key: PublicKey,
}

impl VerifierTokenRequest1 {
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

impl VersionedComponent for VerifierTokenRequest1 {
    const COMPONENT_NAME: &'static str = "VTR";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all database token request versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum VerifierTokenRequestVersion {
    V1(VerifierTokenRequest1),
}

pub struct VerifierTokenRequest {
    pub(crate) version: VerifierTokenRequestVersion,
}

impl VerifierTokenRequest {
    pub fn v1_token_request(public_key: PublicKey) -> Self {
        let request = VerifierTokenRequest1::new(public_key);
        let version = VerifierTokenRequestVersion::V1(request);

        Self::new(version)
    }
}

impl VerifierTokenRequest {
    pub(crate) fn new(version: VerifierTokenRequestVersion) -> VerifierTokenRequest {
        Self { version }
    }
}

impl Digestible for VerifierTokenRequest {
    type Digest = VerifierTokenRequestDigest;
}

impl PemTaggable for VerifierTokenRequest {
    fn tag() -> String {
        "SECUREDNA VERIFIER TOKEN REQUEST".to_string()
    }
}

impl Decode for VerifierTokenRequest {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = VerifierTokenRequestVersion::decode_with_tag_and_constraints(
            decoder,
            tag,
            constraints,
        )?;
        Ok(VerifierTokenRequest::new(version))
    }
}

/// Data that will be signed by the issuer of the VerifierRequest
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
pub(crate) struct VerifierTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) issuance_id: Id,
    pub(crate) identity: CompatibleIdentity,
    pub(crate) expiration: Expiration,
}

impl VerifierTokenIssuer1 {
    pub(crate) fn new(identity: CompatibleIdentity, expiration: Expiration) -> Self {
        let issuance_id = Id::new_random();
        let guard = ComponentVersionGuard::new();
        Self {
            guard,
            issuance_id,
            identity,
            expiration,
        }
    }
}

impl VersionedComponent for VerifierTokenIssuer1 {
    const COMPONENT_NAME: &'static str = "VTI";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all verifier token versions.
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
pub(crate) enum VerifierTokenVersion {
    V1(Signed<TokenData<VerifierTokenRequest1, VerifierTokenIssuer1>>),
}

impl VerifierTokenVersion {
    pub fn public_key(&self) -> &PublicKey {
        match self {
            VerifierTokenVersion::V1(s) => &s.data.request.public_key,
        }
    }
}

/// Token for identifying instances of the hdb
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifierToken<K> {
    pub(crate) version: VerifierTokenVersion,
    key_state: K,
}

impl<K> Digestible for VerifierToken<K> {
    type Digest = VerifierTokenDigest;
}

impl<K> PemTaggable for VerifierToken<K> {
    fn tag() -> String {
        "SECUREDNA VERIFIER TOKEN".to_string()
    }
}

impl VerifierToken<KeyUnavailable> {
    pub(crate) fn new(version: VerifierTokenVersion) -> VerifierToken<KeyUnavailable> {
        Self {
            version,
            key_state: KeyUnavailable,
        }
    }
}

impl Decode for VerifierToken<KeyUnavailable> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version =
            VerifierTokenVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(VerifierToken::new(version))
    }
}

/// Related types for VerifierToken
#[derive(AsnType, Encode, Decode, Debug, Clone, Copy)]
pub struct VerifierTokenGroup;

impl TokenGroup for VerifierTokenGroup {
    type AssociatedRole = Infrastructure;
    type TokenRequest = VerifierTokenRequest;
    type Token = VerifierToken<KeyUnavailable>;
    type ChainType = CertificateChain<Self::AssociatedRole>;

    fn token_kind() -> TokenKind {
        TokenKind::Verifier
    }
}

impl_boilerplate_for_token_request_version! {VerifierTokenRequestVersion, V1}
impl_key_boilerplate_for_token_request_version! {VerifierTokenRequestVersion, V1}

impl_boilerplate_for_token_request! {VerifierTokenRequest}
impl_key_boilerplate_for_token_request! {VerifierTokenRequest}
impl_encoding_boilerplate! {VerifierTokenRequest}

impl_boilerplate_for_token_version! {VerifierTokenVersion, V1}
impl_boilerplate_for_token! {VerifierToken<K>}
impl_encoding_boilerplate! {VerifierToken<K>}
impl_key_boilerplate_for_token! {VerifierToken}

#[cfg(all(test, feature = "cert_tests"))]
mod test {
    use crate::key_traits::{CanLoadSigningKey, HasAssociatedSigningKey, SigningKeyLoaded};
    use crate::{
        Expiration, Infrastructure, SigningKeyPair, VerifierTokenRequest,
        test_helpers::create_leaf_cert,
    };

    #[test]
    fn can_issue_verifier_token() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = SigningKeyPair::new_random();
        let req = VerifierTokenRequest::v1_token_request(kp.public_key());

        cert.issue_verifier_token(req, Expiration::default())
            .unwrap();
    }

    #[test]
    fn verifier_token_has_expected_public_key() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = SigningKeyPair::new_random();
        let req = VerifierTokenRequest::v1_token_request(kp.public_key());

        let token = cert
            .issue_verifier_token(req, Expiration::default())
            .unwrap();

        assert_eq!(&kp.public_key(), token.public_key());
    }

    #[test]
    fn verifier_token_can_sign_with_associated_keypair() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = SigningKeyPair::new_random();
        let req = VerifierTokenRequest::v1_token_request(kp.public_key());

        let token = cert
            .issue_verifier_token(req, Expiration::default())
            .unwrap()
            .load_key(kp)
            .unwrap();

        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }
}
