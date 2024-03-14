// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for creating certificate requests.
//! Private key can be randomly generated or provided.

use rasn::{types::Constraints, AsnType, Decode, Encoder, Tag};
use serde::Serialize;

use crate::{
    certificate::inner::{Intermediate1, Leaf1, RequestBuilderInner, Root1},
    format::Formattable,
    key_state::{KeyAvailable, KeyMismatchError, KeyUnavailable},
    keypair::PublicKey,
    pem::PemTaggable,
    shared_components::{
        common::{Description, Id},
        role::Role,
    },
    HierarchyKind, IssuerAdditionalFields, KeyPair,
};

use super::{
    version_wrappers::{RequestBuilderVersion, RequestVersion},
    Certificate, IssuanceError, RequestDigest,
};

#[derive(Debug)]
pub struct CertificateRequest<R, K>
where
    R: Role,
{
    pub(crate) version: RequestVersion<R>,
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
    pub(crate) fn new(version: RequestVersion<R>) -> CertificateRequest<R, KeyUnavailable> {
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
        let version =
            RequestVersion::<R>::decode_with_tag_and_constraints(decoder, tag, constraints)?;
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

pub struct RequestBuilder<R>(RequestBuilderVersion<R>);

impl<R> RequestBuilder<R>
where
    R: Role,
{
    pub fn root_v1_builder(public_key: PublicKey) -> RequestBuilder<R> {
        let b = RequestBuilderInner::new(Root1::new(), public_key);
        let version = RequestBuilderVersion::RootV1(b);
        RequestBuilder(version)
    }
    pub fn intermediate_v1_builder(public_key: PublicKey) -> RequestBuilder<R> {
        let b = RequestBuilderInner::new(Intermediate1::new(), public_key);
        let version = RequestBuilderVersion::IntermediateV1(b);
        RequestBuilder(version)
    }
    pub fn leaf_v1_builder(public_key: PublicKey) -> RequestBuilder<R> {
        let b = RequestBuilderInner::new(Leaf1::new(), public_key);
        let version = RequestBuilderVersion::LeafV1(b);
        RequestBuilder(version)
    }

    pub fn with_description(self, desc: Description) -> RequestBuilder<R> {
        let version = self.0.with_description(desc);
        Self(version)
    }

    pub fn with_emails_to_notify<T: Into<String>>(
        self,
        emails: impl IntoIterator<Item = T>,
    ) -> RequestBuilder<R> {
        let version = self.0.with_emails_to_notify(emails);
        Self(version)
    }

    pub fn build(self) -> CertificateRequest<R, KeyUnavailable> {
        let version = self.0.build();
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
        Issued, IssuerAdditionalFields, KeyPair,
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
        assert!(matches!(result, Err(DecodeError::UnexpectedPEMTag(_, _))));
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
