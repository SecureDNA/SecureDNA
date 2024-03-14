// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use rasn::{types::Constraints, AsnType, Decode, Decoder, Encode, Encoder, Tag};
use serde::Serialize;

use crate::{
    key_state::KeyUnavailable, pem::PemTaggable, shared_components::role::Role, Certificate,
};

/// Holds a set of certificates which were responsible for issuing a particular certificate.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct CertificateChain<R: Role>(BTreeSet<Certificate<R, KeyUnavailable>>);

impl<R> CertificateChain<R>
where
    R: Role,
{
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    pub fn add_certificate(&mut self, cert: impl Into<Certificate<R, KeyUnavailable>>) {
        self.0.insert(cert.into());
    }

    pub fn from_certificates<I, T>(certs: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Certificate<R, KeyUnavailable>>,
    {
        Self(certs.into_iter().map(|cert| cert.into()).collect())
    }

    pub fn add_certificates<I, T>(&mut self, certs: I)
    where
        I: IntoIterator<Item = T>,
        T: Into<Certificate<R, KeyUnavailable>>,
    {
        self.0.extend(certs.into_iter().map(|cert| cert.into()));
    }

    pub fn add_chain(&mut self, chain: CertificateChain<R>) {
        self.0.extend(chain.0);
    }

    pub fn items(&self) -> impl IntoIterator<Item = &Certificate<R, KeyUnavailable>> {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<R> Default for CertificateChain<R>
where
    R: Role,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R> PemTaggable for CertificateChain<R>
where
    R: Role,
{
    fn tag() -> String {
        format!("SECUREDNA {} CERTIFICATE CHAIN", R::DESCRIPTION)
    }
}

impl<R> AsnType for CertificateChain<R>
where
    R: Role,
{
    const TAG: Tag = Tag::SEQUENCE;
}

impl<R> Encode for CertificateChain<R>
where
    R: Role,
{
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<(), E::Error> {
        self.0
            .encode_with_tag_and_constraints(encoder, tag, constraints)
    }
}

impl<R> Decode for CertificateChain<R>
where
    R: Role,
{
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let certs = Decode::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(CertificateChain(certs))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        asn::{FromASN1DerBytes, ToASN1DerBytes},
        certificate::inner::IssuerAdditionalFields,
        keypair::KeyPair,
        shared_components::role::{Exemption, Infrastructure},
        CertificateChain, DecodeError, Manufacturer, PemDecodable, PemEncodable, RequestBuilder,
        Role,
    };

    #[test]
    fn cannot_der_decode_chain_with_incorrect_role() {
        let chain = make_chain::<Exemption>();
        let data = chain.to_der().unwrap();

        let result = CertificateChain::<Manufacturer>::from_der(data);
        assert!(matches!(result, Err(DecodeError::AsnDecode(_))))
    }

    #[test]
    fn cannot_decode_chains_with_mismatching_pem_role_tag() {
        let chain = make_chain::<Exemption>();
        let encoded = chain.to_pem().unwrap();

        let result = CertificateChain::<Infrastructure>::from_pem(encoded);
        assert!(matches!(result, Err(DecodeError::UnexpectedPEMTag(_, _))));
    }

    #[test]
    fn can_encode_and_decode_infrastructure_cert_chain() {
        let chain = make_chain::<Infrastructure>();
        let encoded = chain.to_pem().unwrap();

        let decoded_chain = CertificateChain::<Infrastructure>::from_pem(encoded).unwrap();
        assert_eq!(chain, decoded_chain)
    }

    #[test]
    fn certificate_chain_der_idempotent() {
        let chain = make_chain::<Infrastructure>();

        let mut rt_chain = chain.clone();
        for _ in 0..100 {
            let der = rt_chain.to_der().unwrap();
            rt_chain = CertificateChain::<Infrastructure>::from_der(der).unwrap();
            assert_eq!(chain, rt_chain);
        }
    }

    #[test]
    fn certificate_chain_pem_idempotent() {
        let chain = make_chain::<Infrastructure>();

        let mut rt_chain = chain.clone();
        for _ in 0..100 {
            let pem = rt_chain.to_pem().unwrap();
            rt_chain = CertificateChain::<Infrastructure>::from_pem(pem).unwrap();
            assert_eq!(chain, rt_chain);
        }
    }

    #[test]
    fn adding_duplicate_cert_does_nothing() {
        let chain = make_chain::<Infrastructure>();

        let kp = KeyPair::new_random();
        let new_root_cert = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        let chain_r = {
            let mut chain_r = chain.clone();
            chain_r.add_certificate(new_root_cert.clone());
            chain_r
        };
        assert_ne!(chain, chain_r);

        let chain_r_r = {
            let mut chain_r_r = chain_r.clone();
            chain_r_r.add_certificate(new_root_cert.clone());
            chain_r_r
        };
        assert_ne!(chain, chain_r_r);
        assert_eq!(chain_r, chain_r_r);
    }

    fn make_chain<R: Role>() -> CertificateChain<R> {
        let kp = KeyPair::new_random();

        let root_cert = RequestBuilder::<R>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req = RequestBuilder::<R>::intermediate_v1_builder(int_kp.public_key()).build();
        let int_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .unwrap();

        CertificateChain::from_certificates(vec![root_cert.into_key_unavailable(), int_cert])
    }
}
