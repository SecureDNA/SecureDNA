// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::pem::PemTaggable;
use crate::{CertificateChain, ChainItem, Role};
use rasn::{AsnType, Decode, Encode};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, AsnType, Encode, Decode)]
pub struct Chain<R>(BTreeSet<ChainItem<R>>)
where
    R: Role;

impl<R: Role> Chain<R> {
    pub fn from_iter<C>(iter: impl IntoIterator<Item = C>) -> Self
    where
        C: Into<ChainItem<R>>,
    {
        let mut set = BTreeSet::new();
        set.extend(iter.into_iter().map(|x| x.into()));
        Self(set)
    }

    pub fn add_item(&mut self, item: impl Into<ChainItem<R>>) {
        self.0.insert(item.into());
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<R: Role> From<CertificateChain<R>> for Chain<R> {
    fn from(value: CertificateChain<R>) -> Self {
        Chain::from_iter(value)
    }
}

impl<'a, R: Role> IntoIterator for &'a Chain<R> {
    type Item = &'a ChainItem<R>;
    type IntoIter = std::collections::btree_set::Iter<'a, ChainItem<R>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<R: Role> IntoIterator for Chain<R> {
    type Item = ChainItem<R>;
    type IntoIter = std::collections::btree_set::IntoIter<ChainItem<R>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<R: Role> PemTaggable for Chain<R> {
    fn tag() -> String {
        format!("SECUREDNA {} CHAIN", R::DESCRIPTION)
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::Chain;
    use crate::{
        asn::{FromASN1DerBytes, ToASN1DerBytes},
        keypair::KeyPair,
        shared_components::role::{Exemption, Infrastructure},
        Builder, CertificateRequest, DecodeError, IssuerAdditionalFields, KeyUnavailable,
        Manufacturer, PemDecodable, PemEncodable, RequestBuilder, Role,
    };

    #[test]
    fn cannot_der_decode_chain_with_incorrect_role() {
        let chain = make_chain::<Exemption>();
        let data = chain.to_der().unwrap();

        let result = Chain::<Manufacturer>::from_der(data);
        assert!(matches!(result, Err(DecodeError::AsnDecode(_))))
    }

    #[test]
    fn cannot_decode_chains_with_mismatching_pem_role_tag() {
        let chain = make_chain::<Exemption>();
        let encoded = chain.to_pem().unwrap();

        let result = Chain::<Infrastructure>::from_pem(encoded);
        assert!(matches!(result, Err(DecodeError::UnexpectedPemTag(_, _))));
    }

    #[test]
    fn can_encode_and_decode_infrastructure_cert_chain() {
        let chain = make_chain::<Infrastructure>();
        let encoded = chain.to_pem().unwrap();

        let decoded_chain = Chain::<Infrastructure>::from_pem(encoded).unwrap();
        assert_eq!(chain, decoded_chain)
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
            chain_r.add_item(new_root_cert.clone());
            chain_r
        };
        assert_ne!(chain, chain_r);

        let chain_r_r = {
            let mut chain_r_r = chain_r.clone();
            chain_r_r.add_item(new_root_cert.clone());
            chain_r_r
        };
        assert_ne!(chain, chain_r_r);
        assert_eq!(chain_r, chain_r_r);
    }

    fn make_chain<R: Role>() -> Chain<R>
    where
        RequestBuilder<R>: Builder<Item = CertificateRequest<R, KeyUnavailable>>,
    {
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

        Chain::from_iter(vec![root_cert.into_key_unavailable(), int_cert])
    }
}
