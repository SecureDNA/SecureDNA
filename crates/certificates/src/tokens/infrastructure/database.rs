// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating `DatabaseTokenRequest` and `DatabaseToken`.
//! A `Certificate` with the `Infrastructure` role is able to sign a `DatabaseTokenRequest` to issue a `DatabaseToken`.
//! `DatabaseToken`s will be used to identify instances of the hdb.

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};

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
    shared_components::common::{
        CompatibleIdentity, ComponentVersionGuard, Expiration, Id, Signed, VersionedComponent,
    },
    tokens::{TokenData, TokenGroup},
    CertificateChain, Digestible, Infrastructure, KeyAvailable, KeyPair, KeyUnavailable, TokenKind,
};

use super::digest::{DatabaseTokenDigest, DatabaseTokenRequestDigest};

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
pub(crate) struct DatabaseTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) request_id: Id,
    pub(crate) public_key: PublicKey,
}

impl DatabaseTokenRequest1 {
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

impl VersionedComponent for DatabaseTokenRequest1 {
    const COMPONENT_NAME: &'static str = "DTR";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all database token request versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum DatabaseTokenRequestVersion {
    V1(DatabaseTokenRequest1),
}

pub struct DatabaseTokenRequest {
    pub(crate) version: DatabaseTokenRequestVersion,
}

impl DatabaseTokenRequest {
    pub fn v1_token_request(public_key: PublicKey) -> Self {
        let request = DatabaseTokenRequest1::new(public_key);
        let version = DatabaseTokenRequestVersion::V1(request);

        Self::new(version)
    }
}

impl DatabaseTokenRequest {
    pub(crate) fn new(version: DatabaseTokenRequestVersion) -> DatabaseTokenRequest {
        Self { version }
    }
}

impl Digestible for DatabaseTokenRequest {
    type Digest = DatabaseTokenRequestDigest;
}

impl PemTaggable for DatabaseTokenRequest {
    fn tag() -> String {
        "SECUREDNA DATABASE TOKEN REQUEST".to_string()
    }
}

impl Decode for DatabaseTokenRequest {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = DatabaseTokenRequestVersion::decode_with_tag_and_constraints(
            decoder,
            tag,
            constraints,
        )?;
        Ok(DatabaseTokenRequest::new(version))
    }
}

/// Data that will be signed by the issuer of the DatabaseRequest
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
pub(crate) struct DatabaseTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) issuance_id: Id,
    pub(crate) identity: CompatibleIdentity,
    pub(crate) expiration: Expiration,
}

impl DatabaseTokenIssuer1 {
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

impl VersionedComponent for DatabaseTokenIssuer1 {
    const COMPONENT_NAME: &'static str = "DTI";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all database token versions.
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
pub(crate) enum DatabaseTokenVersion {
    V1(Signed<TokenData<DatabaseTokenRequest1, DatabaseTokenIssuer1>>),
}

impl DatabaseTokenVersion {
    pub fn public_key(&self) -> &PublicKey {
        match self {
            DatabaseTokenVersion::V1(s) => &s.data.request.public_key,
        }
    }
}

/// Token for identifying instances of the hdb
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DatabaseToken<K> {
    pub(crate) version: DatabaseTokenVersion,
    key_state: K,
}

impl<K> Digestible for DatabaseToken<K> {
    type Digest = DatabaseTokenDigest;
}

impl<K> PemTaggable for DatabaseToken<K> {
    fn tag() -> String {
        "SECUREDNA DATABASE TOKEN".to_string()
    }
}

impl DatabaseToken<KeyUnavailable> {
    pub(crate) fn new(version: DatabaseTokenVersion) -> DatabaseToken<KeyUnavailable> {
        Self {
            version,
            key_state: KeyUnavailable,
        }
    }
}

impl Decode for DatabaseToken<KeyUnavailable> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version =
            DatabaseTokenVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(DatabaseToken::new(version))
    }
}

/// Related types for DatabaseToken
#[derive(AsnType, Encode, Decode, Debug, Clone, Copy)]
pub struct DatabaseTokenGroup;

impl TokenGroup for DatabaseTokenGroup {
    type AssociatedRole = Infrastructure;
    type TokenRequest = DatabaseTokenRequest;
    type Token = DatabaseToken<KeyUnavailable>;
    type ChainType = CertificateChain<Self::AssociatedRole>;

    fn token_kind() -> TokenKind {
        TokenKind::Database
    }
}

impl_boilerplate_for_token_request_version! {DatabaseTokenRequestVersion, V1}
impl_key_boilerplate_for_token_request_version! {DatabaseTokenRequestVersion, V1}

impl_boilerplate_for_token_request! {DatabaseTokenRequest}
impl_key_boilerplate_for_token_request! {DatabaseTokenRequest}
impl_encoding_boilerplate! {DatabaseTokenRequest}

impl_boilerplate_for_token_version! {DatabaseTokenVersion, V1}
impl_boilerplate_for_token! {DatabaseToken<K>}
impl_encoding_boilerplate! {DatabaseToken<K>}
impl_key_boilerplate_for_token! {DatabaseToken}

#[cfg(test)]
mod test {
    use crate::key_traits::{CanLoadKey, HasAssociatedKey, KeyLoaded};
    use crate::{
        test_helpers::create_leaf_cert, DatabaseTokenRequest, Expiration, Infrastructure, KeyPair,
    };

    #[test]
    fn can_issue_database_token() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = DatabaseTokenRequest::v1_token_request(kp.public_key());

        cert.issue_database_token(req, Expiration::default())
            .unwrap();
    }

    #[test]
    fn database_token_has_expected_public_key() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = DatabaseTokenRequest::v1_token_request(kp.public_key());

        let token = cert
            .issue_database_token(req, Expiration::default())
            .unwrap();

        assert_eq!(&kp.public_key(), token.public_key());
    }

    #[test]
    fn database_token_can_sign_with_associated_keypair() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = DatabaseTokenRequest::v1_token_request(kp.public_key());

        let token = cert
            .issue_database_token(req, Expiration::default())
            .unwrap()
            .load_key(kp)
            .unwrap();

        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }
}
