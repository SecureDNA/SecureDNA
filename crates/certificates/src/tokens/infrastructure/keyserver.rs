// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating an `KeyserverTokenRequest`.
//! A `Certificate` with the `Infrastructure` role is able to sign a `KeyserverTokenRequest` to issue a `KeyserverToken`.
//! `KeyserverToken`s will be used to identify keyservers.

use std::fmt::Display;

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};

use doprf::party::KeyserverId;

use crate::validation_failure::ValidationFailure;
use crate::{
    asn::ToASN1DerBytes,
    error::EncodeError,
    impl_boilerplate_for_token, impl_boilerplate_for_token_request,
    impl_boilerplate_for_token_request_version, impl_boilerplate_for_token_version,
    impl_encoding_boilerplate, impl_key_boilerplate_for_token,
    impl_key_boilerplate_for_token_request, impl_key_boilerplate_for_token_request_version,
    issued::Issued,
    keypair::{PublicKey, Signature},
    pem::PemTaggable,
    shared_components::{
        common::{
            CompatibleIdentity, ComponentVersionGuard, Expiration, Id, Signed, VersionedComponent,
        },
        digest::{INDENT, INDENT2},
        role::Infrastructure,
    },
    tokens::{HasAssociatedKey, TokenData, TokenGroup},
    Formattable, KeyAvailable, KeyPair, KeyUnavailable,
};

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rasn(automatic_tags)]
pub(crate) struct KeyserverTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    // This corresponds to the x coordinate of the keyserver's keyshare
    keyserver_id: KeyserverId,
    request_id: Id,
    public_key: PublicKey,
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
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rasn(automatic_tags)]
pub(crate) struct KeyserverTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    issuance_id: Id,
    identity: CompatibleIdentity,
    expiration: Expiration,
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
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyserverToken<K> {
    pub(crate) version: KeyserverTokenVersion,
    key_state: K,
}

impl<K> KeyserverToken<K> {
    pub fn keyserver_id(&self) -> &KeyserverId {
        self.version.keyserver_id()
    }
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

impl Formattable for KeyserverTokenRequest {
    type Digest = KeyserverTokenRequestDigest;
}

#[derive(Serialize)]
pub struct KeyserverTokenRequestDigest {
    version: String,
    keyserver_id: KeyserverId,
    request_id: Id,
    public_key: PublicKey,
}

impl From<KeyserverTokenRequest> for KeyserverTokenRequestDigest {
    fn from(value: KeyserverTokenRequest) -> Self {
        match value.version {
            KeyserverTokenRequestVersion::V1(r) => {
                let version = "V1".to_string();
                let keyserver_id = r.keyserver_id;
                let request_id = r.request_id;
                let public_key = r.public_key;
                KeyserverTokenRequestDigest {
                    version,
                    keyserver_id,
                    request_id,
                    public_key,
                }
            }
        }
    }
}

impl Display for KeyserverTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Keyserver Token Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Keyserver ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.keyserver_id)?;
        Ok(())
    }
}

impl<K> Formattable for KeyserverToken<K> {
    type Digest = KeyserverTokenDigest;
}

#[derive(Serialize)]
pub struct KeyserverTokenDigest {
    version: String,
    request_id: Id,
    issuance_id: Id,
    keyserver_id: KeyserverId,
    public_key: PublicKey,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    signature: Signature,
    validation_failure: Option<ValidationFailure>,
}

impl<K> From<KeyserverToken<K>> for KeyserverTokenDigest {
    fn from(value: KeyserverToken<K>) -> Self {
        let validation_failure = value.validate().err();
        match value.version {
            KeyserverTokenVersion::V1(t) => {
                let version = "V1".to_string();
                let request_id = t.data.request.request_id;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let keyserver_id = t.data.request.keyserver_id;
                let public_key = t.data.request.public_key;
                let expiration = t.data.issuer_fields.expiration;
                let signature = t.signature;
                let issued_by = t.data.issuer_fields.identity;
                KeyserverTokenDigest {
                    version,
                    request_id,
                    issuance_id,
                    keyserver_id,
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

impl Display for KeyserverTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Keyserver Token", self.version)?;
        writeln!(f, "{:INDENT$}Issuance ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issuance_id)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Keyserver ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.keyserver_id)?;
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
    use crate::test_helpers::BreakableSignature;
    use crate::{
        concat_with_newline,
        test_helpers::{create_leaf_cert, expected_keyserver_token_plaintext_display},
        tokens::{CanLoadKey, HasAssociatedKey, KeyLoaded},
        Expiration, FormatMethod, Formattable, Infrastructure, Issued, KeyPair,
        KeyserverTokenRequest,
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
    fn plaintext_display_for_keyserver_token_matches_expected_display() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = KeyserverTokenRequest::v1_token_request(
            kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let token = cert
            .issue_keyserver_token(req, Expiration::default())
            .unwrap();
        let expected_text = expected_keyserver_token_plaintext_display(
            &token,
            "1",
            &format!("(public key: {})", token.issuer_public_key()),
            None,
        );
        let text = token.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn plaintext_display_for_keyserver_token_warns_if_signature_invalid() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = KeyserverTokenRequest::v1_token_request(
            kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let mut token = cert
            .issue_keyserver_token(req, Expiration::default())
            .unwrap();
        token.break_signature();

        let expected_text = expected_keyserver_token_plaintext_display(
            &token,
            "1",
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
