// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use rasn::{AsnType, Decode, Encode};
use thiserror::Error;

use crate::chain::Chain;
use crate::{
    asn::{FromASN1DerBytes, ToASN1DerBytes},
    ChainItem, ChainTraversal, DecodeError, EncodeError, Exemption, ExemptionListTokenGroup,
    MultiItemPemBuilder,
};

use super::TokenGroup;

/// The contents of a token file (for example an .elt file). Holds the token,
/// and the certificate chain showing the provenance of the token.
#[derive(Debug, Clone, AsnType, Encode, Decode)]
pub struct TokenBundle<T>
where
    T: TokenGroup,
{
    pub token: T::Token,
    pub(crate) chain: T::ChainType,
}

impl<T> TokenBundle<T>
where
    T: TokenGroup,
{
    pub fn new(token: T::Token, chain: impl Into<T::ChainType>) -> Self {
        Self {
            token,
            chain: chain.into(),
        }
    }

    /// Serializing for file storage
    pub fn to_file_contents(&self) -> Result<String, EncodeError> {
        let mut pem_items = MultiItemPemBuilder::new();

        pem_items.add_item(&self.token)?;
        pem_items.add_item(&self.chain)?;

        let contents = pem_items.finish();
        Ok(contents)
    }

    /// Parsing from file contents
    pub fn from_file_contents(contents: impl AsRef<[u8]>) -> Result<Self, TokenBundleError> {
        let pem_items = MultiItemPemBuilder::parse(contents)?;

        let token = pem_items
            .find_all::<T::Token>()?
            .into_iter()
            .next()
            .ok_or(TokenBundleError::NoTokenFound)?;

        let chain = pem_items
            .find_all::<T::ChainType>()?
            .into_iter()
            .next()
            .ok_or(TokenBundleError::NoChainFound)?;

        Ok(Self { token, chain })
    }

    /// Serializing for transmission over a network
    pub fn to_wire_format(&self) -> Result<Vec<u8>, EncodeError> {
        self.to_der()
    }

    /// Deserializing after transmission over a network
    pub fn from_wire_format(data: impl AsRef<[u8]>) -> Result<Self, DecodeError> {
        Self::from_der(data)
    }
}

impl<T: TokenGroup> ChainTraversal for TokenBundle<T> {
    type R = T::AssociatedRole;

    fn chain(&self) -> Chain<Self::R> {
        self.chain.clone().into()
    }

    fn bundle_subjects(&self) -> Vec<ChainItem<Self::R>> {
        vec![self.token.clone().into()]
    }
}

impl TokenBundle<ExemptionListTokenGroup> {
    pub fn issue_chain(&self) -> Chain<Exemption> {
        let mut new_chain = self.chain.clone();
        new_chain.add_item(self.token.clone());
        new_chain
    }
}

#[derive(Debug, Error)]
pub enum TokenBundleError {
    #[error("did not find a token when parsing contents")]
    NoTokenFound,
    #[error("did not find a certificate chain when parsing contents")]
    NoChainFound,
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

#[cfg(test)]
mod test {
    use crate::{test_for_all_token_types, PublicKey, TokenBundle, TokenGroup};

    test_for_all_token_types!(token_bundle_serializable_for_file);
    fn token_bundle_serializable_for_file<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
    {
        let (token_bundle, _) = create_token_bundle_fn();

        let contents = token_bundle
            .to_file_contents()
            .expect("could not serialize token bundle for file");

        TokenBundle::<T>::from_file_contents(contents)
            .expect("could not deserialize token bundle from file contents");
    }

    test_for_all_token_types!(token_bundle_serializable_for_wire);
    fn token_bundle_serializable_for_wire<F, T>(create_token_bundle_fn: F)
    where
        F: FnOnce() -> (TokenBundle<T>, PublicKey),
        T: TokenGroup,
    {
        let (token_bundle, _) = create_token_bundle_fn();

        let contents = token_bundle
            .to_wire_format()
            .expect("could not serialize token bundle for wire transmission");

        TokenBundle::<T>::from_wire_format(contents)
            .expect("could not deserialize token bundle from wire format");
    }
}
