// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for creating certificate requests.
//! Private key can be randomly generated or provided.

use rasn::{types::Constraints, AsnType, Decode, Encoder, Tag};
use serde::Serialize;
use std::marker::PhantomData;

use crate::certificate::inner::{ExemptionSubject1, RequestInner, Subject1};
use crate::certificate::{
    ExemptionRequestVersion, InfrastructureRequestVersion, ManufacturerRequestVersion,
    RequestVersion,
};
use crate::{
    certificate::inner::{Intermediate1, Leaf1, Root1},
    format::Formattable,
    key_state::{KeyAvailable, KeyMismatchError, KeyUnavailable},
    keypair::PublicKey,
    pem::PemTaggable,
    shared_components::{
        common::{Description, Id},
        role::Role,
    },
    Exemption, HierarchyKind, Infrastructure, IssuerAdditionalFields, KeyPair, Manufacturer,
};

use super::{Certificate, IssuanceError, RequestDigest};

#[derive(Debug)]
pub struct CertificateRequest<R, K>
where
    R: Role,
{
    pub(crate) version: R::ReqVersion,
    key_state: K,
}

impl<R, K> CertificateRequest<R, K>
where
    R: Role,
{
    pub fn request_id(&self) -> &Id {
        self.version.request_id()
    }

    /// Whether the certificate requests's type is root, intermediate or leaf.
    pub fn hierarchy_level(&self) -> HierarchyKind {
        self.version.hierarchy_level()
    }

    pub fn public_key(&self) -> &PublicKey {
        self.version.public_key()
    }
}

impl<K> CertificateRequest<Exemption, K> {
    pub fn blinding_allowed(&self) -> bool {
        self.version.blinding_allowed()
    }
}

impl<R, K> Serialize for CertificateRequest<R, K>
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

impl<R, K> Formattable for CertificateRequest<R, K>
where
    R: Role,
{
    type Digest = RequestDigest;
}

impl<R> CertificateRequest<R, KeyUnavailable>
where
    R: Role,
{
    pub(crate) fn new(version: R::ReqVersion) -> CertificateRequest<R, KeyUnavailable> {
        Self {
            version,
            key_state: KeyUnavailable,
        }
    }
    pub fn load_key(
        self,
        keypair: KeyPair,
    ) -> Result<CertificateRequest<R, KeyAvailable>, KeyMismatchError> {
        let public_key = self.public_key();
        let key_state = KeyUnavailable::load_key(keypair, public_key)?;
        Ok(CertificateRequest {
            version: self.version,
            key_state,
        })
    }
}

impl<R, K> PemTaggable for CertificateRequest<R, K>
where
    R: Role,
{
    fn tag() -> String {
        format!("SECUREDNA {} CERTIFICATE REQUEST", R::DESCRIPTION)
    }
}

impl<R, K> AsnType for CertificateRequest<R, K>
where
    R: Role,
{
    const TAG: Tag = Tag::SEQUENCE;
}

impl<R, K> rasn::Encode for CertificateRequest<R, K>
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

impl<R> PartialEq for CertificateRequest<R, KeyUnavailable>
where
    R: Role,
{
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl<R> Eq for CertificateRequest<R, KeyUnavailable> where R: Role {}

impl<R> Decode for CertificateRequest<R, KeyUnavailable>
where
    R: Role,
{
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = R::ReqVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self::new(version))
    }
}

impl<R> Clone for CertificateRequest<R, KeyUnavailable>
where
    R: Role,
{
    fn clone(&self) -> Self {
        CertificateRequest::new(self.version.clone())
    }
}

impl<R> CertificateRequest<R, KeyAvailable>
where
    R: Role,
{
    pub fn self_sign(
        self,
        additional_fields: IssuerAdditionalFields,
    ) -> Result<Certificate<R, KeyAvailable>, IssuanceError> {
        let kp = self.key_state.kp();
        let version = self.version.self_sign(additional_fields, kp)?;
        Ok(Certificate {
            version,
            key_state: self.key_state,
        })
    }

    pub fn into_key_unavailable(self) -> CertificateRequest<R, KeyUnavailable> {
        self.into()
    }
}

impl<R> From<CertificateRequest<R, KeyAvailable>> for CertificateRequest<R, KeyUnavailable>
where
    R: Role,
{
    fn from(cert: CertificateRequest<R, KeyAvailable>) -> Self {
        CertificateRequest::new(cert.version)
    }
}

pub struct RequestBuilder<R> {
    pub public_key: PublicKey,
    pub description: Option<Description>,
    pub emails_to_notify: Vec<String>,
    pub allow_blinding: bool,
    pub hierarchy: HierarchyKind,
    pub role: PhantomData<R>,
}

impl<R> RequestBuilder<R> {
    pub fn new(hierarchy: HierarchyKind, public_key: PublicKey) -> Self {
        RequestBuilder {
            public_key,
            description: None,
            hierarchy,
            role: PhantomData::<R>,
            emails_to_notify: vec![],
            allow_blinding: false,
        }
    }

    pub fn with_description(mut self, desc: Description) -> Self {
        self.description = Some(desc);
        self
    }

    pub fn root_v1_builder(public_key: PublicKey) -> RequestBuilder<R> {
        RequestBuilder::new(HierarchyKind::Root, public_key)
    }
    pub fn intermediate_v1_builder(public_key: PublicKey) -> RequestBuilder<R> {
        RequestBuilder::new(HierarchyKind::Intermediate, public_key)
    }
    pub fn leaf_v1_builder(public_key: PublicKey) -> RequestBuilder<R> {
        RequestBuilder::new(HierarchyKind::Leaf, public_key)
    }
}

impl RequestBuilder<Exemption> {
    pub fn with_emails_to_notify<S: Into<String>>(
        mut self,
        emails: impl IntoIterator<Item = S>,
    ) -> Self {
        self.emails_to_notify = emails.into_iter().map(|x| x.into()).collect();
        self
    }

    pub fn allow_blinding(mut self, allow: bool) -> Self {
        self.allow_blinding = allow;
        self
    }
}

pub trait Builder {
    type Item;
    fn build(self) -> Self::Item;
}

impl Builder for RequestBuilder<Exemption> {
    type Item = CertificateRequest<Exemption, KeyUnavailable>;
    fn build(self) -> CertificateRequest<Exemption, KeyUnavailable> {
        let desc = self.description.unwrap_or_default();

        let version = match self.hierarchy {
            HierarchyKind::Root => {
                let subject = ExemptionSubject1::new(
                    desc,
                    self.public_key,
                    self.emails_to_notify,
                    self.allow_blinding,
                );
                let inner = RequestInner::<Root1, Exemption, ExemptionSubject1>::new(subject);
                ExemptionRequestVersion::RootV1(inner)
            }
            HierarchyKind::Intermediate => {
                let subject = ExemptionSubject1::new(
                    desc,
                    self.public_key,
                    self.emails_to_notify,
                    self.allow_blinding,
                );
                let inner =
                    RequestInner::<Intermediate1, Exemption, ExemptionSubject1>::new(subject);
                ExemptionRequestVersion::IntermediateV1(inner)
            }
            HierarchyKind::Leaf => {
                let subject = ExemptionSubject1::new(
                    desc,
                    self.public_key,
                    self.emails_to_notify,
                    self.allow_blinding,
                );
                let inner = RequestInner::<Leaf1, Exemption, ExemptionSubject1>::new(subject);
                ExemptionRequestVersion::LeafV1(inner)
            }
        };
        CertificateRequest::new(version)
    }
}

impl Builder for RequestBuilder<Infrastructure> {
    type Item = CertificateRequest<Infrastructure, KeyUnavailable>;
    fn build(self) -> CertificateRequest<Infrastructure, KeyUnavailable> {
        let desc = self.description.unwrap_or_default();

        let version = match self.hierarchy {
            HierarchyKind::Root => {
                let subject = Subject1::new(desc, self.public_key, vec![]);
                let inner = RequestInner::<Root1, Infrastructure, Subject1>::new(subject);
                InfrastructureRequestVersion::RootV1(inner)
            }
            HierarchyKind::Intermediate => {
                let subject = Subject1::new(desc, self.public_key, vec![]);
                let inner = RequestInner::<Intermediate1, Infrastructure, Subject1>::new(subject);
                InfrastructureRequestVersion::IntermediateV1(inner)
            }
            HierarchyKind::Leaf => {
                let subject = Subject1::new(desc, self.public_key, vec![]);
                let inner = RequestInner::<Leaf1, Infrastructure, Subject1>::new(subject);
                InfrastructureRequestVersion::LeafV1(inner)
            }
        };
        CertificateRequest::new(version)
    }
}

impl Builder for RequestBuilder<Manufacturer> {
    type Item = CertificateRequest<Manufacturer, KeyUnavailable>;

    fn build(self) -> CertificateRequest<Manufacturer, KeyUnavailable> {
        let desc = self.description.unwrap_or_default();

        let version = match self.hierarchy {
            HierarchyKind::Root => {
                let subject = Subject1::new(desc, self.public_key, vec![]);
                let inner = RequestInner::<Root1, Manufacturer, Subject1>::new(subject);
                ManufacturerRequestVersion::RootV1(inner)
            }
            HierarchyKind::Intermediate => {
                let subject = Subject1::new(desc, self.public_key, vec![]);
                let inner = RequestInner::<Intermediate1, Manufacturer, Subject1>::new(subject);
                ManufacturerRequestVersion::IntermediateV1(inner)
            }
            HierarchyKind::Leaf => {
                let subject = Subject1::new(desc, self.public_key, vec![]);
                let inner = RequestInner::<Leaf1, Manufacturer, Subject1>::new(subject);
                ManufacturerRequestVersion::LeafV1(inner)
            }
        };
        CertificateRequest::new(version)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        asn::{FromASN1DerBytes, ToASN1DerBytes},
        certificate::outer::{Certificate, CertificateRequest, RequestBuilder},
        error::DecodeError,
        key_state::KeyUnavailable,
        pem::PemDecodable,
        pem::PemEncodable,
        shared_components::role::{Exemption, Infrastructure, Manufacturer},
        Builder, Issued, IssuerAdditionalFields, KeyPair,
    };

    #[test]
    fn can_load_private_key_on_root_cert_request() {
        let kp: KeyPair = KeyPair::new_random();
        RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap();
    }

    #[test]
    fn cannot_load_incorrect_private_key_on_cert_request() {
        let kp_1 = KeyPair::new_random();
        let kp_2 = KeyPair::new_random();

        RequestBuilder::<Exemption>::root_v1_builder(kp_1.public_key())
            .build()
            .load_key(kp_2)
            .expect_err(
                "attempting to load public key which does not match certificate request should fail",
            );
    }

    #[test]
    fn can_self_sign_root_cert() {
        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default());
        assert!(cert.is_ok())
    }

    #[test]
    fn self_signed_root_cert_has_issuer_field_set_correctly() {
        let kp = KeyPair::new_random();
        let expected_public_key = kp.public_key();
        let cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        assert_eq!(cert.issuer_public_key(), &expected_public_key)
    }

    #[test]
    fn can_encode_and_decode_exemption_cert_request() {
        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key()).build();

        let encoded = req.to_pem().unwrap();
        assert!(encoded.contains("SECUREDNA EXEMPTION CERTIFICATE REQUEST"));

        let decoded_req = CertificateRequest::<Exemption, _>::from_pem(encoded).unwrap();
        assert_eq!(req, decoded_req)
    }

    #[test]
    fn cannot_decode_request_with_mismatching_pem_role_tag() {
        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        let encoded = req.to_pem().unwrap();

        let result = Certificate::<Manufacturer, KeyUnavailable>::from_pem(encoded);
        assert!(matches!(result, Err(DecodeError::UnexpectedPemTag(_, _))));
    }

    #[test]
    fn cannot_der_decode_request_from_incorrect_role() {
        let kp = KeyPair::new_random();
        let root_req = RequestBuilder::<Manufacturer>::root_v1_builder(kp.public_key()).build();

        let data = root_req.to_der().unwrap();

        let result = CertificateRequest::<Infrastructure, _>::from_der(data);
        assert!(matches!(result, Err(DecodeError::AsnDecode(_))))
    }
}
