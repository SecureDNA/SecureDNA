// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating `DatabaseTokenRequest` and `DatabaseToken`.
//! A `Certificate` with the `Infrastructure` role is able to sign a `DatabaseTokenRequest` to issue a `DatabaseToken`.
//! `DatabaseToken`s will be used to identify instances of the hdb.

use std::fmt::Display;

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::validation_failure::ValidationFailure;
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
        digest::{INDENT, INDENT2},
    },
    tokens::{TokenData, TokenGroup},
    CertificateChain, Formattable, Infrastructure, KeyAvailable, KeyPair, KeyUnavailable,
};

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
    request_id: Id,
    public_key: PublicKey,
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
    issuance_id: Id,
    identity: CompatibleIdentity,
    expiration: Expiration,
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

impl Formattable for DatabaseTokenRequest {
    type Digest = DatabaseTokenRequestDigest;
}

#[derive(Serialize)]
pub struct DatabaseTokenRequestDigest {
    version: String,
    request_id: Id,
    public_key: PublicKey,
}

impl From<DatabaseTokenRequest> for DatabaseTokenRequestDigest {
    fn from(value: DatabaseTokenRequest) -> Self {
        match value.version {
            DatabaseTokenRequestVersion::V1(r) => {
                let version = "V1".to_string();
                let request_id = r.request_id;
                let public_key = r.public_key;
                DatabaseTokenRequestDigest {
                    version,
                    request_id,
                    public_key,
                }
            }
        }
    }
}

impl Display for DatabaseTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Database Token Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        Ok(())
    }
}

impl<K> Formattable for DatabaseToken<K> {
    type Digest = DatabaseTokenDigest;
}

#[derive(Serialize)]
pub struct DatabaseTokenDigest {
    version: String,
    request_id: Id,
    issuance_id: Id,
    public_key: PublicKey,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    signature: Signature,
    validation_failure: Option<ValidationFailure>,
}

impl<K> From<DatabaseToken<K>> for DatabaseTokenDigest {
    fn from(value: DatabaseToken<K>) -> Self {
        let validation_failure = value.check_signature_and_expiry().err();
        match value.version {
            DatabaseTokenVersion::V1(t) => {
                let version = "V1".to_string();
                let request_id = t.data.request.request_id;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let public_key = t.data.request.public_key;
                let expiration = t.data.issuer_fields.expiration;
                let signature = t.signature;
                let issued_by = t.data.issuer_fields.identity;
                DatabaseTokenDigest {
                    version,
                    request_id,
                    issuance_id,
                    public_key,
                    expiration,
                    signature,
                    issued_by,
                    validation_failure,
                }
            }
        }
    }
}

impl Display for DatabaseTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Database Token", self.version)?;
        writeln!(f, "{:INDENT$}Issuance ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issuance_id)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Issued by:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issued_by)?;
        write!(f, "{}", self.expiration)?;
        writeln!(f, "{:INDENT$}Signature:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.signature)?;

        if let Some(validation_failure) = &self.validation_failure {
            writeln!(f)?;
            write!(f, "{}", validation_failure)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::key_traits::{CanLoadKey, HasAssociatedKey, KeyLoaded};
    use crate::{
        concat_with_newline,
        test_helpers::{
            create_leaf_cert, expected_database_token_plaintext_display, BreakableSignature,
        },
        DatabaseTokenRequest, Expiration, FormatMethod, Formattable, Infrastructure, Issued,
        KeyPair,
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
    fn plaintext_display_for_database_token_matches_expected_display() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = DatabaseTokenRequest::v1_token_request(kp.public_key());

        let token = cert
            .issue_database_token(req, Expiration::default())
            .unwrap();
        let expected_text = expected_database_token_plaintext_display(
            &token,
            &format!("(public key: {})", token.issuer_public_key()),
            None,
        );
        let text = token.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn plaintext_display_for_database_token_warns_if_signature_invalid() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = DatabaseTokenRequest::v1_token_request(kp.public_key());

        let mut token = cert
            .issue_database_token(req, Expiration::default())
            .unwrap();
        token.break_signature();

        let expected_text = expected_database_token_plaintext_display(
            &token,
            &format!("(public key: {})", token.issuer_public_key()),
            Some(concat_with_newline!(
                "",
                "INVALID: The signature failed verification"
            )),
        );
        let text = token.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text);
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
