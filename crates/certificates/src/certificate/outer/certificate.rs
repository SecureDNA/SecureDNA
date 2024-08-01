// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module defines functionality available for issued certificates.
//! A `Certificate` is able to sign a `CertificateRequest` to issue another `Certificate`.

use std::hash::Hash;

use rasn::types::Constraints;
use rasn::{AsnType, Decode, Encoder, Tag};
use serde::Serialize;

use crate::certificate::CertificateVersion;
use crate::digest::Digestible;
use crate::error::EncodeError;
use crate::issued::Issued;
use crate::key_state::{KeyAvailable, KeyMismatchError, KeyUnavailable};
use crate::key_traits::HasAssociatedKey;
use crate::keypair::{PublicKey, Signature};
use crate::pem::PemTaggable;
use crate::shared_components::common::{Expiration, Id};
use crate::shared_components::role::{Exemption, Infrastructure, Role};
use crate::tokens::exemption::authenticator::Authenticator;
use crate::tokens::exemption::et::{ExemptionToken, ExemptionTokenRequest};
use crate::tokens::infrastructure::keyserver::{KeyserverToken, KeyserverTokenRequest};
use crate::{
    CertificateRequest, DatabaseToken, DatabaseTokenRequest, Description, HierarchyKind, HltToken,
    HltTokenRequest, IssuerAdditionalFields, KeyPair, Manufacturer, SignatureVerificationError,
    SynthesizerToken, SynthesizerTokenRequest,
};

use super::{CertificateDigest, IssuanceError};

/// We can interact with different certificate versions through the `Certificate`.
/// The certificate version is held in a private enum.
#[derive(Debug)]
pub struct Certificate<R: Role, K> {
    pub(crate) version: R::CertVersion,
    pub(crate) key_state: K,
}

impl<R, K> Certificate<R, K>
where
    R: Role,
{
    pub fn public_key(&self) -> &PublicKey {
        self.version.public_key()
    }

    /// Unique for each certificate, created on issuance.
    pub fn issuance_id(&self) -> &Id {
        self.version.issuance_id()
    }

    /// Identifies the certificate request that was used to create the certificate.
    pub fn request_id(&self) -> &Id {
        self.version.request_id()
    }

    /// Whether the certificate's type is root, intermediate or leaf.
    pub fn hierarchy_level(&self) -> HierarchyKind {
        self.version.hierarchy_level()
    }

    pub fn request(&self) -> CertificateRequest<R, KeyUnavailable> {
        CertificateRequest::new(self.version.request().clone())
    }

    pub fn requestor_description(&self) -> &Description {
        self.version.requestor_description()
    }
}

impl<R, K> Issued for Certificate<R, K>
where
    R: Role,
{
    fn issuer_public_key(&self) -> &PublicKey {
        self.version.issuer_public_key()
    }

    fn issuer_description(&self) -> &str {
        self.version.issuer_description()
    }

    fn expiration(&self) -> &Expiration {
        self.version.expiration()
    }

    fn signature(&self) -> &Signature {
        self.version.signature()
    }

    fn data(&self) -> Result<Vec<u8>, EncodeError> {
        self.version.data()
    }

    fn request_id(&self) -> &Id {
        self.version.request_id()
    }

    fn issuance_id(&self) -> &Id {
        self.version.issuance_id()
    }
}

impl<R, K> AsnType for Certificate<R, K>
where
    R: Role,
{
    const TAG: Tag = Tag::SEQUENCE;
}

impl<R, K> rasn::Encode for Certificate<R, K>
where
    R: Role,
{
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<(), E::Error> {
        self.version
            .encode_with_tag_and_constraints(encoder, tag, constraints)
    }
}

impl<R> Decode for Certificate<R, KeyUnavailable>
where
    R: Role,
{
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = R::CertVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self::new(version))
    }
}

impl<R> Hash for Certificate<R, KeyUnavailable>
where
    R: Role,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
    }
}

impl<R, K> PemTaggable for Certificate<R, K>
where
    R: Role,
{
    fn tag() -> String {
        format!("SECUREDNA {} CERTIFICATE", R::DESCRIPTION)
    }
}

impl<R, K> Digestible for Certificate<R, K>
where
    R: Role,
{
    type Digest = CertificateDigest;
}

impl<R, K> Serialize for Certificate<R, K>
where
    R: Role,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.version.serialize(serializer)
    }
}

impl<R> Certificate<R, KeyUnavailable>
where
    R: Role,
{
    pub(crate) fn new(version: R::CertVersion) -> Self {
        Certificate {
            version,
            key_state: KeyUnavailable,
        }
    }

    pub fn load_key(
        self,
        keypair: KeyPair,
    ) -> Result<Certificate<R, KeyAvailable>, KeyMismatchError> {
        let public_key = self.public_key();
        let key_state = KeyUnavailable::load_key(keypair, public_key)?;
        Ok(Certificate {
            version: self.version,
            key_state,
        })
    }
}
impl<R: Role, K> HasAssociatedKey for Certificate<R, K> {
    fn public_key(&self) -> &PublicKey {
        self.public_key()
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureVerificationError> {
        let public_key = self.public_key();
        public_key.verify(message, signature)
    }
}

impl<R> From<Certificate<R, KeyAvailable>> for Certificate<R, KeyUnavailable>
where
    R: Role,
{
    fn from(cert: Certificate<R, KeyAvailable>) -> Self {
        Certificate::new(cert.version)
    }
}

impl<R> Clone for Certificate<R, KeyUnavailable>
where
    R: Role,
{
    fn clone(&self) -> Self {
        Self::new(self.version.clone())
    }
}

impl<R> PartialEq for Certificate<R, KeyUnavailable>
where
    R: Role,
{
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl<R> Eq for Certificate<R, KeyUnavailable> where R: Role {}

impl<R> PartialOrd for Certificate<R, KeyUnavailable>
where
    R: Role,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<R> Ord for Certificate<R, KeyUnavailable>
where
    R: Role,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // only compare version, since KeyUnavailable is ZST
        self.version.cmp(&other.version)
    }
}

impl<R> Certificate<R, KeyAvailable>
where
    R: Role,
{
    pub(crate) fn issue_cert(
        &self,
        req: CertificateRequest<R, KeyUnavailable>,
        additional_fields: IssuerAdditionalFields,
    ) -> Result<Certificate<R, KeyUnavailable>, IssuanceError> {
        let version =
            self.version
                .issue_cert(req.version, additional_fields, self.key_state.kp())?;
        Ok(Certificate::new(version))
    }

    pub fn into_key_unavailable(self) -> Certificate<R, KeyUnavailable> {
        self.into()
    }
}

impl<K> Certificate<Exemption, K> {
    pub fn blinding_allowed(&self) -> bool {
        self.version.blinding_allowed()
    }
}

impl Certificate<Exemption, KeyAvailable> {
    pub(crate) fn issue_exemption_token(
        &self,
        token_request: ExemptionTokenRequest,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
    ) -> Result<ExemptionToken<KeyUnavailable>, IssuanceError> {
        self.version.issue_exemption_token(
            token_request,
            expiration,
            issuer_auth_devices,
            self.key_state.kp(),
        )
    }
}

impl Certificate<Infrastructure, KeyAvailable> {
    pub(crate) fn issue_keyserver_token(
        &self,
        token_request: KeyserverTokenRequest,
        expiration: Expiration,
    ) -> Result<KeyserverToken<KeyUnavailable>, IssuanceError> {
        self.version
            .issue_keyserver_token(token_request, expiration, self.key_state.kp())
    }

    pub(crate) fn issue_database_token(
        &self,
        token_request: DatabaseTokenRequest,
        expiration: Expiration,
    ) -> Result<DatabaseToken<KeyUnavailable>, IssuanceError> {
        self.version
            .issue_database_token(token_request, expiration, self.key_state.kp())
    }

    pub(crate) fn issue_hlt_token(
        &self,
        token_request: HltTokenRequest,
        expiration: Expiration,
    ) -> Result<HltToken<KeyUnavailable>, IssuanceError> {
        self.version
            .issue_hlt_token(token_request, expiration, self.key_state.kp())
    }
}

impl Certificate<Manufacturer, KeyAvailable> {
    pub(crate) fn issue_synthesizer_token(
        &self,
        token_request: SynthesizerTokenRequest,
        expiration: Expiration,
    ) -> Result<SynthesizerToken<KeyUnavailable>, IssuanceError> {
        self.version
            .issue_synthesizer_token(token_request, expiration, self.key_state.kp())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::create_intermediate_bundle;
    use crate::{
        asn::{FromASN1DerBytes, ToASN1DerBytes},
        error::DecodeError,
        pem::{PemDecodable, PemEncodable},
        shared_components::role::{Exemption, Manufacturer},
        test_helpers::create_leaf_bundle,
        Builder, Certificate, Description, Infrastructure, IssuerAdditionalFields, KeyPair,
        RequestBuilder,
    };

    #[test]
    fn can_load_private_key_on_root_cert() {
        let mut private_key_backup = Vec::new();
        KeyPair::new_random()
            .write_key(&mut private_key_backup, "1234")
            .unwrap();
        let kp = KeyPair::load_key(&private_key_backup, "1234").unwrap();
        let cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        let kp = KeyPair::load_key(&private_key_backup, "1234").unwrap();
        cert.load_key(kp).unwrap();
    }

    #[test]
    fn cannot_load_incorrect_private_key_on_root_cert() {
        let kp_1 = KeyPair::new_random();
        let root_req = RequestBuilder::<Exemption>::root_v1_builder(kp_1.public_key())
            .build()
            .load_key(kp_1)
            .unwrap();

        let cert = root_req
            .self_sign(IssuerAdditionalFields::default())
            .expect("couln't self sign")
            .into_key_unavailable();

        let kp_2 = KeyPair::new_random();
        cert.load_key(kp_2).expect_err(
            "attempting to load public key which does not match certificate request should fail",
        );
    }

    #[test]
    fn can_serialise_root_cert_to_pem() {
        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let encoded = cert.to_pem().unwrap();
        Certificate::<Exemption, _>::from_pem(encoded).unwrap();
    }

    #[test]
    fn root_cert_can_sign_intermediate_req() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let intermediate_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let intermediate_cert =
            root_cert.issue_cert(intermediate_req, IssuerAdditionalFields::default());

        assert!(intermediate_cert.is_ok())
    }

    #[test]
    fn intermediate_cert_can_sign_leaf_cert() {
        create_leaf_bundle::<Exemption>();
    }

    #[test]
    fn root_cert_can_not_sign_leaf_req() {
        let root_kp = KeyPair::new_random();
        let root_req = RequestBuilder::<Exemption>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap();

        let root_cert = root_req
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_cert = root_cert.issue_cert(leaf_req, IssuerAdditionalFields::default());

        assert!(leaf_cert.is_err())
    }

    #[test]
    fn can_encode_and_decode_exemption_cert() {
        let root_kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        let encoded = root_cert.to_pem().unwrap();

        assert!(encoded.contains("SECUREDNA EXEMPTION CERTIFICATE"));

        let decoded_cert = Certificate::<Exemption, _>::from_pem(encoded).unwrap();
        assert_eq!(root_cert, decoded_cert)
    }

    #[test]
    fn can_encode_and_decode_manufacturer_cert() {
        let root_kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Manufacturer>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        let encoded = root_cert.to_pem().unwrap();

        assert!(encoded.contains("SECUREDNA MANUFACTURER CERTIFICATE"));

        let decoded_cert = Certificate::<Manufacturer, _>::from_pem(encoded).unwrap();
        assert_eq!(root_cert, decoded_cert)
    }

    #[test]
    fn cannot_decode_cert_with_mismatching_pem_role_tag() {
        let root_kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Manufacturer>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        let encoded = root_cert.to_pem().unwrap();

        let result = Certificate::<Exemption, _>::from_pem(encoded);
        assert!(matches!(result, Err(DecodeError::UnexpectedPemTag(_, _))));
    }

    #[test]
    fn cannot_der_decode_cert_from_incorrect_role() {
        let root_kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        let data = root_cert.to_der().unwrap();

        let result = Certificate::<Manufacturer, _>::from_der(data);
        assert!(matches!(result, Err(DecodeError::AsnDecode(_))))
    }

    #[test]
    fn can_retrieve_exemption_root_request() {
        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .with_description(
                Description::default()
                    .with_name("Mr Test")
                    .with_email("test@example.com")
                    .with_phone_number("12345678901")
                    .with_orcid("888"),
            )
            .build();

        let cert = req
            .clone()
            .load_key(kp)
            .unwrap()
            .self_sign(
                IssuerAdditionalFields::default().with_emails_to_notify(vec!["test2@example.com"]),
            )
            .unwrap();

        let retrieved_req = cert.request();
        assert_eq!(req, retrieved_req)
    }

    #[test]
    fn can_retrieve_infrastructure_intermediate_request() {
        let root_kp = KeyPair::new_random();
        let root = RequestBuilder::<Infrastructure>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Infrastructure>::intermediate_v1_builder(int_kp.public_key())
                .with_description(
                    Description::default()
                        .with_name("Mr Test")
                        .with_email("test@example.com")
                        .with_phone_number("12345678901"),
                )
                .build();

        let int_cert = root
            .issue_cert(int_req.clone(), IssuerAdditionalFields::default())
            .unwrap();

        let retrieved_req = int_cert.request();
        assert_eq!(int_req, retrieved_req)
    }

    #[test]
    fn can_retrieve_manufacturer_leaf_request() {
        let (int_bundle, kp, _) = create_intermediate_bundle::<Manufacturer>();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Manufacturer>::leaf_v1_builder(leaf_kp.public_key())
            .with_description(
                Description::default()
                    .with_name("Mr Test")
                    .with_email("test@example.com")
                    .with_phone_number("12345678901"),
            )
            .build();

        let leaf_cert = int_bundle
            .get_lead_cert()
            .unwrap()
            .clone()
            .load_key(kp)
            .unwrap()
            .issue_cert(leaf_req.clone(), IssuerAdditionalFields::default())
            .unwrap();

        let retrieved_req = leaf_cert.request();
        assert_eq!(leaf_req, retrieved_req)
    }
}
