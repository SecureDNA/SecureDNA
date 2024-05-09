// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating a `HltToken`.
//! A `Certificate` with the `Infrastructure` role is able to sign a `HltTokenRequest` to issue a `HltToken`.
//! `HltToken`s will be used to identify instances of the hazard lookup table.

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
pub(crate) struct HltTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    request_id: Id,
    public_key: PublicKey,
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
    issuance_id: Id,
    identity: CompatibleIdentity,
    expiration: Expiration,
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

impl Formattable for HltTokenRequest {
    type Digest = HltTokenRequestDigest;
}

#[derive(Serialize)]
pub struct HltTokenRequestDigest {
    version: String,
    request_id: Id,
    public_key: PublicKey,
}

impl From<HltTokenRequest> for HltTokenRequestDigest {
    fn from(value: HltTokenRequest) -> Self {
        match value.version {
            HltTokenRequestVersion::V1(r) => {
                let version = "V1".to_string();
                let request_id = r.request_id;
                let public_key = r.public_key;
                HltTokenRequestDigest {
                    version,
                    request_id,
                    public_key,
                }
            }
        }
    }
}

impl Display for HltTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} HLT Token Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        Ok(())
    }
}

impl<K> Formattable for HltToken<K> {
    type Digest = HltTokenDigest;
}

#[derive(Serialize)]
pub struct HltTokenDigest {
    version: String,
    request_id: Id,
    issuance_id: Id,
    public_key: PublicKey,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    signature: Signature,
    validation_failure: Option<ValidationFailure>,
}

impl<K> From<HltToken<K>> for HltTokenDigest {
    fn from(value: HltToken<K>) -> Self {
        let validation_failure = value.check_signature_and_expiry().err();
        match value.version {
            HltTokenVersion::V1(t) => {
                let version = "V1".to_string();
                let request_id = t.data.request.request_id;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let public_key = t.data.request.public_key;
                let expiration = t.data.issuer_fields.expiration;
                let signature = t.signature;
                let issued_by = t.data.issuer_fields.identity;

                HltTokenDigest {
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

impl Display for HltTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} HLT Token", self.version)?;
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
    use crate::test_helpers::BreakableSignature;
    use crate::{
        asn::{FromASN1DerBytes, ToASN1DerBytes},
        concat_with_newline,
        test_helpers::{create_leaf_cert, expected_hlt_token_plaintext_display},
        DatabaseTokenRequest, Expiration, FormatMethod, Formattable, HltTokenRequest,
        Infrastructure, Issued, KeyPair,
    };

    #[test]
    fn can_issue_hlt_token() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = HltTokenRequest::v1_token_request(kp.public_key());

        cert.issue_hlt_token(req, Expiration::default()).unwrap();
    }

    #[test]
    fn plaintext_display_for_hlt_token_matches_expected_display() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = HltTokenRequest::v1_token_request(kp.public_key());

        let token = cert.issue_hlt_token(req, Expiration::default()).unwrap();
        let expected_text = expected_hlt_token_plaintext_display(
            &token,
            &format!("(public key: {})", token.issuer_public_key()),
            None,
        );
        let text = token.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn plaintext_display_for_hlt_token_warns_if_signature_invalid() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = HltTokenRequest::v1_token_request(kp.public_key());

        let mut token = cert.issue_hlt_token(req, Expiration::default()).unwrap();
        token.break_signature();

        let expected_text = expected_hlt_token_plaintext_display(
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
