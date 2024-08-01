// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating an `KeyserverTokenRequest`.
//! A `Certificate` with the `Infrastructure` role is able to sign a `KeyserverTokenRequest` to issue a `KeyserverToken`.
//! `KeyserverToken`s will be used to identify keyservers.

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};

use doprf::party::KeyserverId;

use crate::{
    asn::ToASN1DerBytes,
    error::EncodeError,
    impl_boilerplate_for_token, impl_boilerplate_for_token_request,
    impl_boilerplate_for_token_request_version, impl_boilerplate_for_token_version,
    impl_encoding_boilerplate, impl_key_boilerplate_for_token,
    impl_key_boilerplate_for_token_request, impl_key_boilerplate_for_token_request_version,
    issued::Issued,
    key_traits::HasAssociatedKey,
    keypair::{PublicKey, Signature},
    pem::PemTaggable,
    shared_components::{
        common::{
            CompatibleIdentity, ComponentVersionGuard, Expiration, Id, Signed, VersionedComponent,
        },
        role::Infrastructure,
    },
    tokens::{TokenData, TokenGroup},
    CertificateChain, Digestible, KeyAvailable, KeyPair, KeyUnavailable, TokenKind,
};

use super::digest::{KeyserverTokenDigest, KeyserverTokenRequestDigest};

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
pub(crate) struct KeyserverTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    // This corresponds to the x coordinate of the keyserver's keyshare
    pub(crate) keyserver_id: KeyserverId,
    pub(crate) request_id: Id,
    pub(crate) public_key: PublicKey,
}

impl KeyserverTokenRequest1 {
    pub fn new(public_key: PublicKey, keyserver_id: KeyserverId) -> Self {
        let guard = ComponentVersionGuard::new();
        let request_id = Id::new_random();
        Self {
            guard,
            keyserver_id,
            request_id,
            public_key,
        }
    }
}

impl VersionedComponent for KeyserverTokenRequest1 {
    const COMPONENT_NAME: &'static str = "KTR";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all keyserver token request versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum KeyserverTokenRequestVersion {
    V1(KeyserverTokenRequest1),
}

pub struct KeyserverTokenRequest {
    pub(crate) version: KeyserverTokenRequestVersion,
}

impl KeyserverTokenRequest {
    pub fn v1_token_request(public_key: PublicKey, keyserver_id: KeyserverId) -> Self {
        let request = KeyserverTokenRequest1::new(public_key, keyserver_id);
        let version = KeyserverTokenRequestVersion::V1(request);
        Self::new(version)
    }
}

impl KeyserverTokenRequest {
    pub(crate) fn new(version: KeyserverTokenRequestVersion) -> KeyserverTokenRequest {
        Self { version }
    }
}

impl Digestible for KeyserverTokenRequest {
    type Digest = KeyserverTokenRequestDigest;
}

impl PemTaggable for KeyserverTokenRequest {
    fn tag() -> String {
        "SECUREDNA KEYSERVER TOKEN REQUEST".to_string()
    }
}

impl Decode for KeyserverTokenRequest {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = KeyserverTokenRequestVersion::decode_with_tag_and_constraints(
            decoder,
            tag,
            constraints,
        )?;
        Ok(KeyserverTokenRequest::new(version))
    }
}

/// The data that will be signed by the issuer of the KeyserverRequest
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
pub(crate) struct KeyserverTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) issuance_id: Id,
    pub(crate) identity: CompatibleIdentity,
    pub(crate) expiration: Expiration,
}

impl KeyserverTokenIssuer1 {
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

impl VersionedComponent for KeyserverTokenIssuer1 {
    const COMPONENT_NAME: &'static str = "KTI";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all keyserver token versions.
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
    Serialize,
    Deserialize,
    Hash,
)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum KeyserverTokenVersion {
    V1(Signed<TokenData<KeyserverTokenRequest1, KeyserverTokenIssuer1>>),
}

impl KeyserverTokenVersion {
    pub fn public_key(&self) -> &PublicKey {
        match self {
            KeyserverTokenVersion::V1(s) => &s.data.request.public_key,
        }
    }
    pub fn keyserver_id(&self) -> &KeyserverId {
        match self {
            KeyserverTokenVersion::V1(s) => &s.data.request.keyserver_id,
        }
    }
}

/// Token for identifying keyservers
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyserverToken<K> {
    pub(crate) version: KeyserverTokenVersion,
    key_state: K,
}

impl<K> KeyserverToken<K> {
    pub fn keyserver_id(&self) -> &KeyserverId {
        self.version.keyserver_id()
    }
}

impl<K> Digestible for KeyserverToken<K> {
    type Digest = KeyserverTokenDigest;
}

impl<K> PemTaggable for KeyserverToken<K> {
    fn tag() -> String {
        "SECUREDNA KEYSERVER TOKEN".to_string()
    }
}

impl KeyserverToken<KeyUnavailable> {
    pub(crate) fn new(version: KeyserverTokenVersion) -> KeyserverToken<KeyUnavailable> {
        Self {
            version,
            key_state: KeyUnavailable,
        }
    }
}

impl Decode for KeyserverToken<KeyUnavailable> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version =
            KeyserverTokenVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(KeyserverToken::new(version))
    }
}

/// Related types for KeyserverToken
#[derive(AsnType, Encode, Decode, Debug, Clone, Copy)]
pub struct KeyserverTokenGroup;

impl TokenGroup for KeyserverTokenGroup {
    type AssociatedRole = Infrastructure;
    type TokenRequest = KeyserverTokenRequest;
    type Token = KeyserverToken<KeyUnavailable>;
    type ChainType = CertificateChain<Self::AssociatedRole>;

    fn token_kind() -> TokenKind {
        TokenKind::Keyserver
    }
}

impl_boilerplate_for_token_request_version! {KeyserverTokenRequestVersion, V1}
impl_key_boilerplate_for_token_request_version! {KeyserverTokenRequestVersion, V1}

impl_boilerplate_for_token_request! {KeyserverTokenRequest}
impl_encoding_boilerplate! {KeyserverTokenRequest}
impl_key_boilerplate_for_token_request! {KeyserverTokenRequest}

impl_boilerplate_for_token_version! {KeyserverTokenVersion, V1}
impl_boilerplate_for_token! {KeyserverToken<K>}
impl_encoding_boilerplate! {KeyserverToken<K>}
impl_key_boilerplate_for_token! {KeyserverToken}

#[cfg(test)]
mod test {
    use crate::key_traits::{CanLoadKey, HasAssociatedKey, KeyLoaded};
    use crate::{
        test_helpers::create_leaf_cert, Expiration, Infrastructure, KeyPair, KeyserverTokenRequest,
    };
    use doprf::party::KeyserverId;

    #[test]
    fn can_issue_keyserver_token() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = KeyserverTokenRequest::v1_token_request(
            kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        cert.issue_keyserver_token(req, Expiration::default())
            .unwrap();
    }

    #[test]
    fn keyserver_token_has_expected_public_key() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = KeyserverTokenRequest::v1_token_request(
            kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let token = cert
            .issue_keyserver_token(req, Expiration::default())
            .unwrap();

        assert_eq!(&kp.public_key(), token.public_key());
    }

    #[test]
    fn keyserver_token_has_expected_keyserver_id() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = KeyserverTokenRequest::v1_token_request(
            kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let token = cert
            .issue_keyserver_token(req, Expiration::default())
            .unwrap();

        assert_eq!(token.keyserver_id(), &KeyserverId::try_from(1).unwrap());
    }

    #[test]
    fn keyserver_token_can_sign_with_associated_keypair() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = KeyserverTokenRequest::v1_token_request(
            kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let token = cert
            .issue_keyserver_token(req, Expiration::default())
            .unwrap()
            .load_key(kp)
            .unwrap();

        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }
}
