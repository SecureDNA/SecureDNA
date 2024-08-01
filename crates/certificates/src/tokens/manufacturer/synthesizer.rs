// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating an `SynthesizerTokenRequest`.
//! A `Certificate` with the `Manufacturer` role is able to sign a `SynthesizerTokenRequest` to issue a `SynthesizerToken`.

use std::str::FromStr;

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    asn::ToASN1DerBytes,
    ecies::{EncryptionKeyParseError, EncryptionPublicKey},
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
    CertificateChain, Digestible, KeyAvailable, KeyPair, KeyUnavailable, Manufacturer, TokenKind,
};

use super::digest::{SynthesizerTokenDigest, SynthesizerTokenRequestDigest};

/// Represents a recipient in the context of an audit process. This struct encapsulates the necessary
/// information to securely send encrypted audit data. It includes the recipient's email and their
/// public key for encryption.
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
pub struct AuditRecipient {
    pub(crate) email: String,
    pub(crate) public_key: EncryptionPublicKey,
}

impl AuditRecipient {
    pub fn new(
        email: impl Into<String>,
        public_key: impl Into<String>,
    ) -> Result<Self, EncryptionKeyParseError> {
        let public_key = EncryptionPublicKey::from_str(&public_key.into())?;
        Ok(Self {
            email: email.into(),
            public_key,
        })
    }
}

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
pub(crate) struct SynthesizerTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) request_id: Id,
    pub(crate) public_key: PublicKey,
    pub(crate) manufacturer_domain: String,
    pub(crate) model: String,
    pub(crate) serial_number: String,
    pub(crate) max_dna_base_pairs_per_day: u64,
    pub(crate) audit_recipient: Option<AuditRecipient>,
}

impl SynthesizerTokenRequest1 {
    pub fn new(
        public_key: PublicKey,
        manufacturer_domain: String,
        model: String,
        serial_number: String,
        max_dna_base_pairs_per_day: u64,
        audit_recipient: Option<AuditRecipient>,
    ) -> Self {
        let guard = ComponentVersionGuard::new();
        let request_id = Id::new_random();
        Self {
            guard,
            request_id,
            public_key,
            manufacturer_domain,
            model,
            serial_number,
            max_dna_base_pairs_per_day,
            audit_recipient,
        }
    }
}

impl VersionedComponent for SynthesizerTokenRequest1 {
    const COMPONENT_NAME: &'static str = "STR";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all synthesizer token request versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum SynthesizerTokenRequestVersion {
    V1(SynthesizerTokenRequest1),
}

pub struct SynthesizerTokenRequest {
    pub(crate) version: SynthesizerTokenRequestVersion,
}

impl SynthesizerTokenRequest {
    pub fn v1_token_request(
        public_key: PublicKey,
        manufacturer_domain: impl Into<String>,
        model: impl Into<String>,
        serial_number: impl Into<String>,
        max_dna_base_pairs_per_day: u64,
        audit_recipient: Option<AuditRecipient>,
    ) -> Self {
        let request = SynthesizerTokenRequest1::new(
            public_key,
            manufacturer_domain.into(),
            model.into(),
            serial_number.into(),
            max_dna_base_pairs_per_day,
            audit_recipient,
        );
        let version = SynthesizerTokenRequestVersion::V1(request);

        Self::new(version)
    }
}

impl SynthesizerTokenRequest {
    pub(crate) fn new(version: SynthesizerTokenRequestVersion) -> SynthesizerTokenRequest {
        Self { version }
    }
}

impl Digestible for SynthesizerTokenRequest {
    type Digest = SynthesizerTokenRequestDigest;
}

impl PemTaggable for SynthesizerTokenRequest {
    fn tag() -> String {
        "SECUREDNA SYNTHESIZER TOKEN REQUEST".to_string()
    }
}

impl Decode for SynthesizerTokenRequest {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = SynthesizerTokenRequestVersion::decode_with_tag_and_constraints(
            decoder,
            tag,
            constraints,
        )?;
        Ok(SynthesizerTokenRequest::new(version))
    }
}

/// Data that will be signed by the issuer of the SynthesizerRequest
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
pub(crate) struct SynthesizerTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) issuance_id: Id,
    pub(crate) identity: CompatibleIdentity,
    pub(crate) expiration: Expiration,
}

impl SynthesizerTokenIssuer1 {
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

impl VersionedComponent for SynthesizerTokenIssuer1 {
    const COMPONENT_NAME: &'static str = "STI";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all synthesizer token versions.
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
pub(crate) enum SynthesizerTokenVersion {
    V1(Signed<TokenData<SynthesizerTokenRequest1, SynthesizerTokenIssuer1>>),
}

impl SynthesizerTokenVersion {
    pub fn public_key(&self) -> &PublicKey {
        match self {
            SynthesizerTokenVersion::V1(s) => &s.data.request.public_key,
        }
    }

    pub fn manufacturer_domain(&self) -> &String {
        match self {
            SynthesizerTokenVersion::V1(s) => &s.data.request.manufacturer_domain,
        }
    }

    pub fn model(&self) -> &String {
        match self {
            SynthesizerTokenVersion::V1(s) => &s.data.request.model,
        }
    }

    pub fn serial_number(&self) -> &String {
        match self {
            SynthesizerTokenVersion::V1(s) => &s.data.request.serial_number,
        }
    }

    pub fn max_dna_base_pairs_per_day(&self) -> u64 {
        match self {
            SynthesizerTokenVersion::V1(s) => s.data.request.max_dna_base_pairs_per_day,
        }
    }
}

/// Token to identify benchtop synthesizers
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SynthesizerToken<K> {
    pub(crate) version: SynthesizerTokenVersion,
    key_state: K,
}

impl<K> SynthesizerToken<K> {
    pub fn manufacturer_domain(&self) -> &String {
        self.version.manufacturer_domain()
    }

    pub fn model(&self) -> &String {
        self.version.model()
    }

    pub fn serial_number(&self) -> &String {
        self.version.serial_number()
    }

    pub fn max_dna_base_pairs_per_day(&self) -> u64 {
        self.version.max_dna_base_pairs_per_day()
    }
}

impl<K> Digestible for SynthesizerToken<K> {
    type Digest = SynthesizerTokenDigest;
}

impl<K> PemTaggable for SynthesizerToken<K> {
    fn tag() -> String {
        "SECUREDNA SYNTHESIZER TOKEN".to_string()
    }
}

impl SynthesizerToken<KeyUnavailable> {
    pub(crate) fn new(version: SynthesizerTokenVersion) -> SynthesizerToken<KeyUnavailable> {
        Self {
            version,
            key_state: KeyUnavailable,
        }
    }
}

impl Decode for SynthesizerToken<KeyUnavailable> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version =
            SynthesizerTokenVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(SynthesizerToken::new(version))
    }
}

/// Related types for SynthesizerToken
#[derive(AsnType, Encode, Decode, Debug, Clone, Copy)]
pub struct SynthesizerTokenGroup;

impl TokenGroup for SynthesizerTokenGroup {
    type AssociatedRole = Manufacturer;
    type TokenRequest = SynthesizerTokenRequest;
    type Token = SynthesizerToken<KeyUnavailable>;
    type ChainType = CertificateChain<Self::AssociatedRole>;

    fn token_kind() -> TokenKind {
        TokenKind::Synthesizer
    }
}

impl_boilerplate_for_token_request_version! {SynthesizerTokenRequestVersion, V1}
impl_key_boilerplate_for_token_request_version! {SynthesizerTokenRequestVersion, V1}

impl_boilerplate_for_token_request! {SynthesizerTokenRequest}
impl_key_boilerplate_for_token_request! {SynthesizerTokenRequest}
impl_encoding_boilerplate! {SynthesizerTokenRequest}

impl_boilerplate_for_token_version! {SynthesizerTokenVersion, V1}
impl_boilerplate_for_token! {SynthesizerToken<K>}
impl_encoding_boilerplate! {SynthesizerToken<K>}
impl_key_boilerplate_for_token! {SynthesizerToken}

#[cfg(test)]
mod test {
    use crate::key_traits::{CanLoadKey, HasAssociatedKey, KeyLoaded};
    use crate::test_helpers::create_intermediate_bundle;
    use crate::{
        test_helpers::{
            create_leaf_cert, create_synth_token_request, expected_synthesizer_token_display,
        },
        tokens::manufacturer::synthesizer::AuditRecipient,
        Builder, Description, Digestible, Expiration, Issued, IssuerAdditionalFields, KeyPair,
        Manufacturer, RequestBuilder, SynthesizerTokenRequest,
    };

    #[test]
    fn can_issue_synthesizer_token() {
        let cert = create_leaf_cert::<Manufacturer>();
        let (req, _) = create_synth_token_request();
        cert.issue_synthesizer_token(req, Expiration::default())
            .unwrap();
    }

    #[test]
    fn plaintext_display_for_synthesizer_token_with_audit_recipient_matches_expected_display() {
        let cert = create_leaf_cert::<Manufacturer>();
        let kp = KeyPair::new_random();

        // Public key is hex encoded libsecp256k1 key
        // Created via ecies::utils::generate_keypair()
        let audit_recipient = AuditRecipient::new(
            "anna@example.com",
            "03f29057c21d3eb14815eefa0127895b57278fd41c2bad78861ff7a5b1c9b5adae",
        )
        .unwrap();
        let req = SynthesizerTokenRequest::v1_token_request(
            kp.public_key(),
            "maker.synth",
            "XL",
            "10AK",
            10_000u64,
            Some(audit_recipient),
        );
        let token = cert
            .issue_synthesizer_token(req, Expiration::default())
            .unwrap();
        let expected_text = expected_synthesizer_token_display(
            &token,
            "maker.synth",
            "XL",
            "10AK",
            "10000 base pairs per day",
            Some("anna@example.com (03f29057c21d3eb14815eefa0127895b57278fd41c2bad78861ff7a5b1c9b5adae)"),
            &format!("(public key: {})", token.issuer_public_key()),
        );
        let text = token.into_digest().to_string();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn synthesizer_token_has_expected_public_key() {
        let cert: crate::Certificate<Manufacturer, crate::KeyAvailable> =
            create_leaf_cert::<Manufacturer>();
        let (req, kp) = create_synth_token_request();

        let token = cert
            .issue_synthesizer_token(req, Expiration::default())
            .unwrap();

        assert_eq!(&kp.public_key(), token.public_key());
    }

    #[test]
    fn can_access_expected_fields_on_synth_token() {
        let cert = create_leaf_cert::<Manufacturer>();
        let kp = KeyPair::new_random();

        let domain = "maker.synth";
        let model = "XL";
        let serial_number = "10AK";
        let max_dna_base_pairs_per_day = 10_000_000u64;

        let req = SynthesizerTokenRequest::v1_token_request(
            kp.public_key(),
            domain,
            model,
            serial_number,
            max_dna_base_pairs_per_day,
            None,
        );

        let token = cert
            .issue_synthesizer_token(req, Expiration::default())
            .unwrap();

        assert_eq!(token.manufacturer_domain(), domain);
        assert_eq!(token.model(), model);
        assert_eq!(token.serial_number(), serial_number);
        assert_eq!(
            token.max_dna_base_pairs_per_day(),
            max_dna_base_pairs_per_day
        );
    }

    #[test]
    fn synthesizer_token_can_sign_with_associated_keypair() {
        let cert = create_leaf_cert::<Manufacturer>();
        let (req, kp) = create_synth_token_request();

        let token = cert
            .issue_synthesizer_token(req, Expiration::default())
            .unwrap()
            .load_key(kp)
            .unwrap();

        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }

    #[test]
    fn can_access_issuer_description_on_synthesizer_token() {
        let (int_bundle, int_kp, _) = create_intermediate_bundle::<Manufacturer>();

        let leaf_kp = KeyPair::new_random();

        let leaf_req = RequestBuilder::<Manufacturer>::leaf_v1_builder(leaf_kp.public_key())
            .with_description(
                Description::default()
                    .with_name("A Company")
                    .with_email("a.company@example.com"),
            )
            .build();

        let leaf_cert = int_bundle
            .get_lead_cert()
            .unwrap()
            .clone()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .unwrap();

        let (req, _) = create_synth_token_request();

        let token = leaf_cert
            .load_key(leaf_kp)
            .unwrap()
            .issue_synthesizer_token(req, Expiration::default())
            .unwrap();

        assert_eq!(
            token.issuer_description(),
            "A Company, a.company@example.com"
        )
    }
}
