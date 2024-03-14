// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structs holding with certificates and certificate request versions.

use std::hash::Hash;
use std::marker::PhantomData;

use rasn::{AsnType, Decode, Encode};
use serde::Serialize;
use thiserror::Error;

use crate::certificate::inner::{
    CertificateInner, Intermediate1, Issuer1, Leaf1, RequestBuilderInner, RequestInner, Root1,
    Subject1,
};
use crate::error::EncodeError;
use crate::key_state::KeyUnavailable;
use crate::keypair::{PublicKey, Signature};
use crate::shared_components::common::{Description, Expiration, Id};
use crate::shared_components::role::{Exemption, Infrastructure, Role, RoleGuard};
use crate::tokens::exemption::authenticator::Authenticator;
use crate::tokens::exemption::exemption_list::{
    ExemptionListToken, ExemptionListTokenRequest, ExemptionListTokenRequestVersion,
    ExemptionListTokenVersion,
};
use crate::tokens::infrastructure::{
    database::{
        DatabaseToken, DatabaseTokenRequest, DatabaseTokenRequestVersion, DatabaseTokenVersion,
    },
    hlt::{HltToken, HltTokenRequest, HltTokenRequestVersion, HltTokenVersion},
    keyserver::{
        KeyserverToken, KeyserverTokenRequest, KeyserverTokenRequestVersion, KeyserverTokenVersion,
    },
};
use crate::tokens::manufacturer::synthesizer::{
    SynthesizerToken, SynthesizerTokenRequest, SynthesizerTokenRequestVersion,
    SynthesizerTokenVersion,
};
use crate::{HierarchyKind, IssuerAdditionalFields, KeyPair, Manufacturer};

#[derive(
    Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord, Clone,
)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum CertificateVersion<R>
where
    R: Role,
{
    RootV1(CertificateInner<Root1, R, Subject1, Issuer1>),
    IntermediateV1(CertificateInner<Intermediate1, R, Subject1, Issuer1>),
    LeafV1(CertificateInner<Leaf1, R, Subject1, Issuer1>),
    // LeafV2(CertificateInner<Leaf2, R, Subject1, Issuer1>)
}

macro_rules! impl_issued_boilerplate {
    ($name:ident, $($variant:ident),+) => {
        impl<R> $name<R>  where R: Role {
            pub(crate) fn signature(&self) -> &Signature {
                match self {
                    $(Self::$variant(c) => c.signature(),)+
                }
            }

            pub(crate) fn issuer_public_key(&self) -> &PublicKey {
                match self {
                    $(Self::$variant(c) => c.issuer_public_key(),)+
                }
            }

            pub(crate) fn issuer_description(&self) -> &str {
                match self {
                    $(Self::$variant(c) => c.issuer_description(),)+
                }
            }

            pub(crate) fn expiration(&self) -> &Expiration {
                match self {
                    $(Self::$variant(c) => c.expiration(),)+
                }
            }

            pub(crate) fn data(&self) -> Result<Vec<u8>, EncodeError> {
                match self {
                    $(Self::$variant(c) => c.data(),)+
                }
            }

            pub(crate) fn issuance_id(&self) -> &Id {
                match self {
                    $(Self::$variant(c) => c.issuance_id(),)+
                }
            }

            pub(crate) fn request_id(&self) -> &Id {
                match self {
                    $(Self::$variant(c) => c.request_id(),)+
                }
            }
        }
    }
}

impl_issued_boilerplate!(CertificateVersion, LeafV1, IntermediateV1, RootV1);

impl<R> CertificateVersion<R>
where
    R: Role,
{
    pub(crate) fn public_key(&self) -> &PublicKey {
        match self {
            Self::RootV1(c) => c.public_key(),
            Self::IntermediateV1(c) => c.public_key(),
            Self::LeafV1(c) => c.public_key(),
        }
    }

    pub(crate) fn hierarchy_level(&self) -> HierarchyKind {
        match self {
            Self::RootV1(_) => HierarchyKind::Root,
            Self::IntermediateV1(_) => HierarchyKind::Intermediate,
            Self::LeafV1(_) => HierarchyKind::Leaf,
        }
    }
}

impl<R> CertificateVersion<R>
where
    R: Role,
{
    pub(crate) fn issue_cert(
        &self,
        request: RequestVersion<R>,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<CertificateVersion<R>, IssuanceError> {
        match (self, request) {
            (Self::RootV1(root), RequestVersion::IntermediateV1(req)) => {
                let cert = root.issue_intermediate(req, additional_fields, kp)?;
                let version = CertificateVersion::IntermediateV1(cert);
                Ok(version)
            }
            (Self::IntermediateV1(intermediate), RequestVersion::IntermediateV1(req)) => {
                let cert = intermediate.issue_other_intermediate(req, additional_fields, kp)?;
                let version = CertificateVersion::IntermediateV1(cert);
                Ok(version)
            }
            (Self::IntermediateV1(intermediate), RequestVersion::LeafV1(req)) => {
                let cert = intermediate.issue_leaf(req, additional_fields, kp)?;
                let version = CertificateVersion::LeafV1(cert);
                Ok(version)
            }
            (_, request) => Err(IssuanceError::HierarchyError(
                self.hierarchy_level().to_string(),
                request.hierarchy_level().to_string(),
            )),
        }
    }

    pub fn request(&self) -> RequestVersion<R> {
        match self {
            CertificateVersion::RootV1(root) => {
                let request_subject = root.0.data.common.subject.clone();
                RequestVersion::RootV1(RequestInner {
                    hierarchy_level: Root1::new(),
                    role: RoleGuard(PhantomData::<R>),
                    subject: request_subject,
                })
            }
            CertificateVersion::IntermediateV1(int) => {
                let request_subject = int.0.data.common.subject.clone();
                RequestVersion::IntermediateV1(RequestInner {
                    hierarchy_level: Intermediate1::new(),
                    role: RoleGuard(PhantomData::<R>),
                    subject: request_subject,
                })
            }
            CertificateVersion::LeafV1(leaf) => {
                let request_subject = leaf.0.data.common.subject.clone();
                RequestVersion::LeafV1(RequestInner {
                    hierarchy_level: Leaf1::new(),
                    role: RoleGuard(PhantomData::<R>),
                    subject: request_subject,
                })
            }
        }
    }
}
impl CertificateVersion<Exemption> {
    pub(crate) fn issue_elt(
        &self,
        token_request: ExemptionListTokenRequest,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
        kp: &KeyPair,
    ) -> Result<ExemptionListToken, IssuanceError> {
        match self {
            CertificateVersion::LeafV1(c) => match token_request.version {
                ExemptionListTokenRequestVersion::V1(r) => {
                    let token = c.issue_elt(r, expiration, issuer_auth_devices, kp)?;
                    Ok(ExemptionListToken {
                        version: ExemptionListTokenVersion::V1(token),
                    })
                }
            },
            _ => Err(IssuanceError::NonLeafIssuingToken(
                self.hierarchy_level().to_string(),
                "exemption list".to_owned(),
            )),
        }
    }
}

impl CertificateVersion<Infrastructure> {
    pub(crate) fn issue_keyserver_token(
        &self,
        token_request: KeyserverTokenRequest,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<KeyserverToken<KeyUnavailable>, IssuanceError> {
        match self {
            CertificateVersion::LeafV1(c) => match token_request.version {
                KeyserverTokenRequestVersion::V1(req) => {
                    let token = c.issue_keyserver_token(req, expiration, kp)?;
                    Ok(KeyserverToken::new(KeyserverTokenVersion::V1(token)))
                }
            },
            _ => Err(IssuanceError::NonLeafIssuingToken(
                self.hierarchy_level().to_string(),
                "keyserver".to_string(),
            )),
        }
    }

    pub(crate) fn issue_database_token(
        &self,
        token_request: DatabaseTokenRequest,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<DatabaseToken<KeyUnavailable>, IssuanceError> {
        match self {
            CertificateVersion::LeafV1(c) => match token_request.version {
                DatabaseTokenRequestVersion::V1(req) => {
                    let token = c.issue_database_token(req, expiration, kp)?;
                    Ok(DatabaseToken::new(DatabaseTokenVersion::V1(token)))
                }
            },
            _ => Err(IssuanceError::NonLeafIssuingToken(
                self.hierarchy_level().to_string(),
                "database".to_string(),
            )),
        }
    }

    pub(crate) fn issue_hlt_token(
        &self,
        token_request: HltTokenRequest,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<HltToken<KeyUnavailable>, IssuanceError> {
        match self {
            CertificateVersion::LeafV1(c) => match token_request.version {
                HltTokenRequestVersion::V1(req) => {
                    let token = c.issue_hlt_token(req, expiration, kp)?;
                    Ok(HltToken::new(HltTokenVersion::V1(token)))
                }
            },
            _ => Err(IssuanceError::NonLeafIssuingToken(
                self.hierarchy_level().to_string(),
                "HLT".to_string(),
            )),
        }
    }
}

impl CertificateVersion<Manufacturer> {
    pub(crate) fn issue_synthesizer_token(
        &self,
        token_request: SynthesizerTokenRequest,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<SynthesizerToken<KeyUnavailable>, IssuanceError> {
        match self {
            CertificateVersion::LeafV1(c) => match token_request.version {
                SynthesizerTokenRequestVersion::V1(req) => {
                    let token = c.issue_synthesizer_token(req, expiration, kp)?;
                    Ok(SynthesizerToken::new(SynthesizerTokenVersion::V1(token)))
                }
            },
            _ => Err(IssuanceError::NonLeafIssuingToken(
                self.hierarchy_level().to_string(),
                "synthesizer".to_string(),
            )),
        }
    }
}

#[derive(Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Clone)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum RequestVersion<R>
where
    R: Role,
{
    RootV1(RequestInner<Root1, R, Subject1>),
    IntermediateV1(RequestInner<Intermediate1, R, Subject1>),
    LeafV1(RequestInner<Leaf1, R, Subject1>),
    // LeafV2(RequestInner<Leaf2, R, Subject1>),
}

impl<R> RequestVersion<R>
where
    R: Role,
{
    pub(crate) fn request_id(&self) -> &Id {
        match self {
            Self::RootV1(c) => c.request_id(),
            Self::IntermediateV1(c) => c.request_id(),
            Self::LeafV1(c) => c.request_id(),
        }
    }

    pub(crate) fn hierarchy_level(&self) -> HierarchyKind {
        match self {
            Self::RootV1(_) => HierarchyKind::Root,
            Self::IntermediateV1(_) => HierarchyKind::Intermediate,
            Self::LeafV1(_) => HierarchyKind::Leaf,
        }
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        match self {
            RequestVersion::RootV1(c) => c.public_key(),
            RequestVersion::IntermediateV1(c) => c.public_key(),
            RequestVersion::LeafV1(c) => c.public_key(),
        }
    }
}

impl<R> RequestVersion<R>
where
    R: Role,
{
    pub(crate) fn self_sign(
        self,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<CertificateVersion<R>, IssuanceError> {
        match self {
            Self::RootV1(root) => {
                let inner = root.self_sign(additional_fields, kp)?;
                Ok(CertificateVersion::RootV1(inner))
            }
            _ => Err(IssuanceError::NotAbleToSelfSign(
                self.hierarchy_level().to_string(),
            )),
        }
    }
}

pub(crate) enum RequestBuilderVersion<R> {
    RootV1(RequestBuilderInner<Root1, R>),
    IntermediateV1(RequestBuilderInner<Intermediate1, R>),
    LeafV1(RequestBuilderInner<Leaf1, R>),
}

impl<R> RequestBuilderVersion<R> {
    pub(crate) fn with_description(self, desc: Description) -> RequestBuilderVersion<R> {
        match self {
            Self::RootV1(b) => RequestBuilderVersion::RootV1(b.with_description(desc)),
            Self::IntermediateV1(b) => {
                RequestBuilderVersion::IntermediateV1(b.with_description(desc))
            }
            Self::LeafV1(b) => RequestBuilderVersion::LeafV1(b.with_description(desc)),
        }
    }

    pub fn with_emails_to_notify<T: Into<String>>(
        self,
        emails: impl IntoIterator<Item = T>,
    ) -> RequestBuilderVersion<R> {
        match self {
            Self::RootV1(b) => Self::RootV1(b.with_emails_to_notify(emails)),
            Self::IntermediateV1(b) => Self::IntermediateV1(b.with_emails_to_notify(emails)),
            Self::LeafV1(b) => Self::LeafV1(b.with_emails_to_notify(emails)),
        }
    }

    pub(crate) fn build(self) -> RequestVersion<R>
    where
        R: Role,
    {
        match self {
            Self::RootV1(b) => {
                let req = b.build();
                RequestVersion::RootV1(req)
            }
            Self::IntermediateV1(b) => {
                let req = b.build();
                RequestVersion::IntermediateV1(req)
            }
            Self::LeafV1(b) => {
                let req = b.build();
                RequestVersion::LeafV1(req)
            }
        }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum IssuanceError {
    #[error("a {} certificate cannot sign a {} request", .0, .1)]
    HierarchyError(String, String),
    #[error("a {} certificate cannot issue a {} token. A leaf certificate is required", .0, .1)]
    NonLeafIssuingToken(String, String),
    #[error("a {} certificate request cannot self sign", .0)]
    NotAbleToSelfSign(String),
    #[error(transparent)]
    Encode(#[from] EncodeError),
}
