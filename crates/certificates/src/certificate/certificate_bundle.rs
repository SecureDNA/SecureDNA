// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use itertools::Itertools;
use rasn::{AsnType, Decode, Encode};
use thiserror::Error;

use crate::asn::{FromASN1DerBytes, ToASN1DerBytes};
use crate::error::EncodeError;
use crate::issued::Issued;
use crate::pem::MultiItemPemBuilder;
use crate::validation_error::ValidationError;
use crate::{
    error::DecodeError, shared_components::role::Role, CertificateChain, ChainItem, ChainTraversal,
};
use crate::{
    Authenticator, CertificateRequest, DatabaseTokenGroup, DatabaseTokenRequest, Exemption,
    ExemptionTokenGroup, ExemptionTokenRequest, Expiration, HierarchyKind, HltTokenGroup,
    HltTokenRequest, Infrastructure, IssuanceError, IssuerAdditionalFields, KeyMismatchError,
    KeyPair, KeyserverTokenGroup, KeyserverTokenRequest, Manufacturer, SynthesizerTokenGroup,
    SynthesizerTokenRequest, TokenBundle,
};

use crate::certificate::outer::Certificate;
use crate::chain::Chain;
use crate::key_state::KeyUnavailable;

/// The contents of a .cert file. Holds the main certificate(s) (multiple in the case of cross signed certificates),
/// and the certificate chain showing the provenance of the certificate.
#[derive(AsnType, Encode, Decode, PartialEq, Debug)]
pub struct CertificateBundle<R>
where
    R: Role,
{
    pub certs: Vec<Certificate<R, KeyUnavailable>>,
    chain: CertificateChain<R>,
}

#[derive(Debug, Error, PartialEq)]
pub enum CertificateBundleError {
    #[error("unable to merge, certificates are not derived from the same request")]
    MergeError,
    #[error("no valid certificates present: {0}")]
    InvalidCertificate(ValidationError),
    #[error("did not find a certificate when parsing contents")]
    NoCertificateFound,
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    KeyMismatch(#[from] KeyMismatchError),
    #[error(transparent)]
    Issuance(#[from] IssuanceError),
}

#[derive(Debug, Error, PartialEq)]
pub enum CertificateError<R: Role> {
    #[error("no valid certificates present: {1}")]
    Invalid(Box<Certificate<R, KeyUnavailable>>, ValidationError),
    #[error("did not find a certificate")]
    NotFound,
}

impl<R: Role> From<CertificateError<R>> for CertificateBundleError {
    fn from(e: CertificateError<R>) -> Self {
        match e {
            CertificateError::Invalid(_, err) => CertificateBundleError::InvalidCertificate(err),
            CertificateError::NotFound => CertificateBundleError::NoCertificateFound,
        }
    }
}

impl<R> CertificateBundle<R>
where
    R: Role,
{
    pub fn new(
        cert: impl Into<Certificate<R, KeyUnavailable>>,
        chain: Option<CertificateChain<R>>,
    ) -> Self {
        let chain = chain.unwrap_or_default();
        Self {
            certs: vec![cert.into()],
            chain,
        }
    }

    /// If a certificate has been cross-signed the `CertificateBundle` may hold more than one certificate - all
    /// representing the same certificate request, but issued by different parties.
    // We can use any of these to issue a new certificate because they all have the same public key.
    // However we choose the certificate with the longest validity period in order to avoid unneccessary CLI warnings.
    pub fn get_lead_cert(&self) -> Result<&Certificate<R, KeyUnavailable>, CertificateError<R>> {
        let mut first_error: Option<(Certificate<R, KeyUnavailable>, ValidationError)> = None;

        for cert in self
            .certs
            .iter()
            .sorted_by_key(|c| -c.expiration().not_valid_after)
        {
            match cert.check_signature_and_expiry() {
                Ok(_) => return Ok(cert),
                Err(e) => {
                    first_error.get_or_insert((cert.clone(), e));
                }
            }
        }

        first_error
            .map(|(cert, err)| Err(CertificateError::Invalid(Box::new(cert), err)))
            .unwrap_or(Err(CertificateError::NotFound))
    }

    pub fn issue_cert_bundle(
        &self,
        request: CertificateRequest<R, KeyUnavailable>,
        additional_fields: IssuerAdditionalFields,
        key: KeyPair,
    ) -> Result<CertificateBundle<R>, CertificateBundleError> {
        let cert = self.get_lead_cert()?.clone().load_key(key)?;
        let new_cert = cert.issue_cert(request, additional_fields)?;
        let chain = match cert.hierarchy_level() {
            // Root certs don't need to provide a certificate chain for the certificates they issue, because the root public keys will be known.
            HierarchyKind::Root => None,
            _ => Some(self.issue_chain()),
        };
        Ok(CertificateBundle::new(new_cert, chain))
    }

    /// Chain provided to any certificate or token issued by this certificate.
    pub fn issue_chain(&self) -> CertificateChain<R> {
        let mut new_chain = self.chain.clone();
        new_chain.add_items(self.certs.clone());
        new_chain
    }

    /// Serializing for file storage
    pub fn to_file_contents(&self) -> Result<String, EncodeError> {
        let mut pem_items = MultiItemPemBuilder::new();

        for cert in self.certs.iter() {
            pem_items.add_item(cert)?;
        }

        if !self.chain.is_empty() {
            pem_items.add_item(&self.chain)?;
        }

        let contents = pem_items.finish();
        Ok(contents)
    }

    /// Parsing from file contents
    pub fn from_file_contents(contents: impl AsRef<[u8]>) -> Result<Self, CertificateBundleError> {
        let pem_items = MultiItemPemBuilder::parse(contents)?;

        let certs = pem_items.find_all::<Certificate<R, KeyUnavailable>>()?;
        if certs.is_empty() {
            return Err(CertificateBundleError::NoCertificateFound);
        }

        let chain = pem_items
            .find_all::<CertificateChain<R>>()?
            .into_iter()
            .next()
            .unwrap_or_default();

        Ok(Self { certs, chain })
    }

    /// Serializing for transmission over a network
    pub fn to_wire_format(&self) -> Result<Vec<u8>, EncodeError> {
        self.to_der()
    }

    /// Deserializing after transmission over a network
    pub fn from_wire_format(data: impl AsRef<[u8]>) -> Result<Self, DecodeError> {
        Self::from_der(data)
    }

    pub fn merge(
        mut self,
        other: CertificateBundle<R>,
    ) -> Result<CertificateBundle<R>, CertificateBundleError>
    where
        R: Role,
    {
        let certs: Vec<_> = self.certs.into_iter().chain(other.certs).collect();

        let request = certs.first().unwrap().request();
        if certs.iter().any(|x| x.request() != request) {
            return Err(CertificateBundleError::MergeError);
        }

        self.chain.add_chain(other.chain);

        Ok(CertificateBundle {
            certs,
            chain: self.chain,
        })
    }
}

impl CertificateBundle<Exemption> {
    pub fn issue_exemption_token_bundle(
        &self,
        token_request: ExemptionTokenRequest,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
        keypair: KeyPair,
    ) -> Result<TokenBundle<ExemptionTokenGroup>, CertificateBundleError> {
        let token = self
            .get_lead_cert()?
            .clone()
            .load_key(keypair)?
            .issue_exemption_token(token_request, expiration, issuer_auth_devices)?;
        let chain = self.issue_chain();
        Ok(TokenBundle::new(token, chain))
    }
}

impl CertificateBundle<Infrastructure> {
    pub fn issue_keyserver_token_bundle(
        &self,
        token_request: KeyserverTokenRequest,
        expiration: Expiration,
        keypair: KeyPair,
    ) -> Result<TokenBundle<KeyserverTokenGroup>, CertificateBundleError> {
        let token = self
            .get_lead_cert()?
            .clone()
            .load_key(keypair)?
            .issue_keyserver_token(token_request, expiration)?;
        let chain = self.issue_chain();
        Ok(TokenBundle::new(token, chain))
    }

    pub fn issue_database_token_bundle(
        &self,
        token_request: DatabaseTokenRequest,
        expiration: Expiration,
        keypair: KeyPair,
    ) -> Result<TokenBundle<DatabaseTokenGroup>, CertificateBundleError> {
        let token = self
            .get_lead_cert()?
            .clone()
            .load_key(keypair)?
            .issue_database_token(token_request, expiration)?;
        let chain = self.issue_chain();
        Ok(TokenBundle::new(token, chain))
    }

    pub fn issue_hlt_token_bundle(
        &self,
        token_request: HltTokenRequest,
        expiration: Expiration,
        keypair: KeyPair,
    ) -> Result<TokenBundle<HltTokenGroup>, CertificateBundleError> {
        let token = self
            .get_lead_cert()?
            .clone()
            .load_key(keypair)?
            .issue_hlt_token(token_request, expiration)?;
        let chain = self.issue_chain();
        Ok(TokenBundle::new(token, chain))
    }
}

impl CertificateBundle<Manufacturer> {
    pub fn issue_synthesizer_token_bundle(
        &self,
        token_request: SynthesizerTokenRequest,
        expiration: Expiration,
        keypair: KeyPair,
    ) -> Result<TokenBundle<SynthesizerTokenGroup>, CertificateBundleError> {
        let token = self
            .get_lead_cert()?
            .clone()
            .load_key(keypair)?
            .issue_synthesizer_token(token_request, expiration)?;
        let chain = self.issue_chain();
        Ok(TokenBundle::new(token, chain))
    }
}

impl<R: Role> ChainTraversal for CertificateBundle<R> {
    type R = R;

    fn bundle_subjects(&self) -> Vec<ChainItem<Self::R>> {
        self.certs.iter().map(|c| c.clone().into()).collect()
    }

    fn chain(&self) -> Chain<Self::R> {
        self.chain.clone().into()
    }
}

#[cfg(test)]
mod tests {
    use crate::certificate::inner::IssuerAdditionalFields;
    use crate::certificate::RequestBuilder;
    use crate::keypair::KeyPair;
    use crate::shared_components::role::Exemption;
    use crate::Infrastructure;
    use crate::{Builder, CertificateChain};

    use crate::test_helpers::create_leaf_bundle;
    use crate::CertificateBundle;

    #[test]
    fn can_pem_encode_cert_bundle_with_empty_chain() {
        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        let encoded = CertificateBundle::new(cert.clone(), None)
            .to_file_contents()
            .unwrap();
        let file_contents = CertificateBundle::from_file_contents(encoded).unwrap();

        assert!(file_contents.certs.contains(&cert));
        assert_eq!(file_contents.chain, CertificateChain::new());
    }

    #[test]
    fn can_pem_encode_cert_bundle_with_chain() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let int_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .unwrap();

        let mut chain = CertificateChain::new();
        chain.add_item(root_cert);

        let encoded = CertificateBundle::new(int_cert.clone(), Some(chain.clone()))
            .to_file_contents()
            .expect("could not serialize certificate bundle for file");
        let file_contents = CertificateBundle::from_file_contents(encoded)
            .expect("could not deserialize certificate bundle from file contents");

        assert!(file_contents.certs.contains(&int_cert));
        assert_eq!(file_contents.chain, chain);
    }

    #[test]
    fn can_wire_encode_cert_and_chain() {
        let (cert_bundle, _, _) = create_leaf_bundle::<Infrastructure>();

        let encoded_cb = cert_bundle
            .to_wire_format()
            .expect("could not serialize certificate bundle for wire transmission");

        let decoded_cb = CertificateBundle::<Infrastructure>::from_wire_format(encoded_cb)
            .expect("could not deserialize certificate bundle from wire format");
        assert_eq!(cert_bundle, decoded_cb)
    }

    #[test]
    fn get_lead_cert_selects_cert_with_longest_validity() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let int_req_copy = int_req.clone();

        let issuer_fields_for_a = IssuerAdditionalFields::default()
            .with_expiry_in_days(1)
            .unwrap();
        let issuer_fields_for_b = IssuerAdditionalFields::default()
            .with_expiry_in_days(2)
            .unwrap();

        let int_cert_a = root_cert.issue_cert(int_req, issuer_fields_for_a).unwrap();

        let int_cert_b = root_cert
            .issue_cert(int_req_copy, issuer_fields_for_b)
            .unwrap();

        let cert_bundle_a = CertificateBundle::new(int_cert_a, None);
        let cert_bundle_b = CertificateBundle::new(int_cert_b.clone(), None);

        let cert_bundle = cert_bundle_a.merge(cert_bundle_b).unwrap();

        let lead_cert = cert_bundle.get_lead_cert().unwrap();
        assert_eq!(*lead_cert, int_cert_b);
    }
}
