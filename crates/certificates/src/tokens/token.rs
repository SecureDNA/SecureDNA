// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fmt::Display, hash::Hash, str::FromStr};

use rasn::{AsnType, Decode, Encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chain::Chain;
use crate::pem::PemTaggable;
use crate::{
    asn::AsnCompatible,
    chain_item::ChainItem,
    issued::Issued,
    pem::{PemDecodable, PemEncodable},
    shared_components::{common::Id, role::Role},
    CertificateChain, Formattable,
};

/// Groups related types for each token
pub trait TokenGroup: AsnCompatible // where
//     Chain<Self::ChainType>: PemTaggable,
{
    /// Role of token's issuing certificate chain
    type AssociatedRole: Role + AsnCompatible;
    type TokenRequest: Request + PemEncodable + PemDecodable + Formattable;
    type Token: Issued
        + PemEncodable
        + PemDecodable
        + Formattable
        + AsnCompatible
        + Clone
        + Into<ChainItem<Self::AssociatedRole>>;

    type ChainType: AsnCompatible
        + PemTaggable
        + Clone
        + From<CertificateChain<Self::AssociatedRole>>
        + Into<Chain<Self::AssociatedRole>>;
}

pub trait Request {
    fn request_id(&self) -> &Id;
}

/// Tokens which can be issued by leaf certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    ExemptionList,
    Keyserver,
    Database,
    Hlt,
    Synthesizer,
}

impl Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenKind::ExemptionList => write!(f, "exemption list token"),
            TokenKind::Keyserver => write!(f, "keyserver token"),
            TokenKind::Database => write!(f, "database token"),
            TokenKind::Hlt => write!(f, "HLT token"),
            TokenKind::Synthesizer => write!(f, "synthesizer list"),
        }
    }
}

#[derive(Error, Debug)]
#[error("could not parse token type, expected one of (exemption-list, keyserver, database, synthesizer, hlt)")]
pub struct TokenKindParseError;
impl FromStr for TokenKind {
    type Err = TokenKindParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exemption-list" => Ok(TokenKind::ExemptionList),
            "keyserver" => Ok(TokenKind::Keyserver),
            "database" => Ok(TokenKind::Database),
            "hlt" => Ok(TokenKind::Hlt),
            "synthesizer" => Ok(TokenKind::Synthesizer),
            _ => Err(TokenKindParseError),
        }
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
//tsgen
pub struct TokenData<Q, I> {
    pub(crate) request: Q,
    pub(crate) issuer_fields: I,
}

/// Implements functions that exist on all token's inner version.
#[macro_export]
macro_rules! impl_boilerplate_for_token_version {
    ($name:ident, $($variant:ident),+) => {
        impl $name {
            pub(crate) fn request_id(&self) -> &Id {
                match self {
                    $(Self::$variant(t) => &t.data.request.request_id,)+
                }
            }

            pub(crate) fn issuance_id(&self) -> &Id {
                match self {
                    $(Self::$variant(t) => &t.data.issuer_fields.issuance_id,)+
                }
            }

            pub(crate) fn signature(&self) -> &Signature {
                match self {
                    $(Self::$variant(t) => &t.signature,)+
                }
            }

            pub(crate) fn issuer_public_key(&self) -> &PublicKey {
                match self {
                    $(Self::$variant(t) => &t.data.issuer_fields.identity.pk,)+
                }
            }

            pub(crate) fn issuer_description(&self) -> &str {
                match self {
                    $(Self::$variant(t) => &t.data.issuer_fields.identity.desc,)+
                }
            }

            pub(crate) fn expiration(&self) -> &Expiration {
                match self {
                    $(Self::$variant(c) => &c.data.issuer_fields.expiration,)+
                }
            }

            pub(crate) fn data(&self) -> Result<Vec<u8>, EncodeError> {
                match self {
                    $(Self::$variant(t) => t.data.to_der(),)+
                }
            }
        }
    }
}
/// Implements functions that exist on all token requests' inner version.
#[macro_export]
macro_rules! impl_boilerplate_for_token_request_version {
    ($name:ident, $($variant:ident),+) => {
        impl $name {
            pub(crate) fn request_id(&self) -> &Id {
                match self {
                    $(Self::$variant(t) => &t.request_id,)+
                }
            }
        }
    }
}

/// Implements key functionality on token requests' inner version. Not required by all tokens.
#[macro_export]
macro_rules! impl_key_boilerplate_for_token_request_version {
    ($name:ident, $($variant:ident),+) => {
        impl $name {
            pub(crate) fn public_key(&self) -> &PublicKey {
                match self {
                    $(Self::$variant(t) => &t.public_key,)+
                }
            }
        }
    }
}

/// Implements functions that exist on all token requests.
#[macro_export]
macro_rules! impl_boilerplate_for_token_request {
    ($name:ident) => {
        impl $crate::Request for $name {
            fn request_id(&self) -> &Id {
                &self.version.request_id()
            }
        }
    };
}

/// Implements key functionality for token request. This is only required by some tokens.
#[macro_export]
macro_rules! impl_key_boilerplate_for_token_request {
    ($name:ident) => {
        impl $name {
            pub fn public_key(&self) -> &PublicKey {
                self.version.public_key()
            }
        }
    };
}

/// Implements functions that exist on all tokens.
#[macro_export]
macro_rules! impl_boilerplate_for_token {
    ($name:ident $(< $generic:ident >)?) => {
        impl $(<$generic>)? Issued for $name $(<$generic>)? {
            fn signature(&self) -> &Signature {
                self.version.signature()
            }

            fn issuer_public_key(&self) -> &PublicKey {
                self.version.issuer_public_key()
            }

            fn issuer_description(&self) -> &str {
                self.version.issuer_description()
            }

            fn expiration(&self) -> &Expiration {
                self.version.expiration()
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

        impl $(<$generic>)? std::hash::Hash for $name $(<$generic>)? {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.version.hash(state);
            }
        }
    };
}

/// Implements encoding functionality which is needed by both tokens and token requests.
#[macro_export]
macro_rules! impl_encoding_boilerplate {
    ($name:ident $(< $generic:ident >)?) => {
        impl $(<$generic>)? AsnType for $name $(<$generic>)? {
            const TAG: Tag = Tag::SEQUENCE;
        }

        impl $(<$generic>)? Encode for $name $(<$generic>)? {
            fn encode_with_tag_and_constraints<E: rasn::Encoder>(
                &self,
                encoder: &mut E,
                tag: Tag,
                constraints: Constraints,
            ) -> Result<(), E::Error> {
                self.version
                    .encode_with_tag_and_constraints(encoder, tag, constraints)
            }
        }

        impl $(<$generic>)? Serialize for $name $(<$generic>)? {

            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: serde::Serializer,
            {
                    self.version.serialize(serializer)
            }
        }
    }
}

/// Implements key functionality. This is only required by some tokens.
#[macro_export]
macro_rules! impl_key_boilerplate_for_token {
    ($name:ident) => {
        impl<K> $crate::key_traits::HasAssociatedKey for $name<K> {
            fn public_key(&self) -> &PublicKey {
                self.version.public_key()
            }

            /// Used to verify signatures created by the token
            fn verify(
                &self,
                message: &[u8],
                signature: &Signature,
            ) -> Result<(), $crate::SignatureVerificationError> {
                self.public_key().verify(message, signature)
            }
        }
        impl $crate::key_traits::CanLoadKey for $name<KeyUnavailable> {
            type KeyAvailableType = $name<KeyAvailable>;

            /// Expects PEM encoded keypair bytes
            fn load_key(
                self,
                keypair: KeyPair,
            ) -> Result<$name<KeyAvailable>, $crate::KeyMismatchError> {
                let public_key = self.public_key();
                let key_state = KeyUnavailable::load_key(keypair, public_key)?;
                Ok($name {
                    version: self.version,
                    key_state,
                })
            }
        }
        impl $crate::key_traits::KeyLoaded for $name<KeyAvailable> {
            type KeyUnavailableType = $name<KeyUnavailable>;
            fn into_key_unavailable(self) -> Self::KeyUnavailableType {
                $name {
                    version: self.version,
                    key_state: KeyUnavailable,
                }
            }
            fn sign(&self, message: &[u8]) -> Signature {
                let kp = self.key_state.kp();
                kp.sign(message)
            }
        }
    };
}
