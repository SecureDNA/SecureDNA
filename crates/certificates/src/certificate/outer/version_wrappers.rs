// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structs holding with certificates and certificate request versions.

use std::fmt::Debug;
use std::hash::Hash;

use rasn::{AsnType, Decode, Encode};
use serde::Serialize;
use thiserror::Error;

use crate::certificate::inner::{
    CertificateInner, ExemptionSubject1, Intermediate1, Issuer1, Leaf1, RequestInner, Root1,
    Subject1,
};
use crate::error::EncodeError;
use crate::key_state::KeyUnavailable;
use crate::keypair::{PublicKey, Signature};
use crate::shared_components::common::{Expiration, Id};
use crate::shared_components::role::{Exemption, Infrastructure};
use crate::tokens::exemption::authenticator::Authenticator;
use crate::tokens::exemption::exemption_list::{
    ExemptionListToken, ExemptionListTokenRequest, ExemptionListTokenRequestVersion,
    ExemptionListTokenVersion, NonCompliantEltr,
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
use crate::validation_failure::ValidationFailure;
use crate::{
    CertificateDigest, HierarchyKind, IssuerAdditionalFields, KeyPair, Manufacturer, RequestDigest,
};

/// Each role-specific implementor of `CertificateVersion` is an enum whose variants
/// allow us to deserialize a certificate without knowing its hierarchy level or version.
pub trait CertificateVersion:
    Debug
    + AsnType
    + Encode
    + Decode
    + Serialize
    + PartialEq
    + Eq
    + Hash
    + PartialOrd
    + Ord
    + Clone
    + Send
    + Sync
{
    type ReqVersion: RequestVersion;

    fn signature(&self) -> &Signature;
    fn issuer_public_key(&self) -> &PublicKey;
    fn issuer_description(&self) -> &str;
    fn expiration(&self) -> &Expiration;
    fn data(&self) -> Result<Vec<u8>, EncodeError>;
    fn issuance_id(&self) -> &Id;
    fn request_id(&self) -> &Id;
    fn request(&self) -> Self::ReqVersion;
    fn public_key(&self) -> &PublicKey;
    fn hierarchy_level(&self) -> HierarchyKind;

    fn issue_cert(
        &self,
        request: Self::ReqVersion,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<Self, IssuanceError>;

    fn into_digest(self, role: &str, failure: Option<ValidationFailure>) -> CertificateDigest;
}
/// Allows exemption certificate versioning
#[derive(
    Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord, Clone,
)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum ExemptionCertificateVersion {
    RootV1(CertificateInner<Root1, Exemption, ExemptionSubject1, Issuer1>),
    IntermediateV1(CertificateInner<Intermediate1, Exemption, ExemptionSubject1, Issuer1>),
    LeafV1(CertificateInner<Leaf1, Exemption, ExemptionSubject1, Issuer1>),
}

/// Allows manufacturer certificate versioning
#[derive(
    Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord, Clone,
)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum ManufacturerCertificateVersion {
    RootV1(CertificateInner<Root1, Manufacturer, Subject1, Issuer1>),
    IntermediateV1(CertificateInner<Intermediate1, Manufacturer, Subject1, Issuer1>),
    LeafV1(CertificateInner<Leaf1, Manufacturer, Subject1, Issuer1>),
}

/// Allows infrastructure certificate versioning
#[derive(
    Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord, Clone,
)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum InfrastructureCertificateVersion {
    RootV1(CertificateInner<Root1, Infrastructure, Subject1, Issuer1>),
    IntermediateV1(CertificateInner<Intermediate1, Infrastructure, Subject1, Issuer1>),
    LeafV1(CertificateInner<Leaf1, Infrastructure, Subject1, Issuer1>),
}

/// Provides an implementation of `CertificateVersion` in order to avoid boilerplate
macro_rules! impl_certificate_version_boilerplate {
    ($name:ident, $assoc_type:ty, $($variant:ident),+) => {

        impl CertificateVersion for $name {
            type ReqVersion = $assoc_type;
            fn signature(&self) -> &Signature {
                match self {
                    $(Self::$variant(c) => c.signature(),)+
                }
            }

            fn issuer_public_key(&self) -> &PublicKey {
                match self {
                    $(Self::$variant(c) => c.issuer_public_key(),)+
                }
            }

            fn issuer_description(&self) -> &str {
                match self {
                    $(Self::$variant(c) => c.issuer_description(),)+
                }
            }

            fn expiration(&self) -> &Expiration {
                match self {
                    $(Self::$variant(c) => c.expiration(),)+
                }
            }

            fn data(&self) -> Result<Vec<u8>, EncodeError> {
                match self {
                    $(Self::$variant(c) => c.data(),)+
                }
            }

            fn issuance_id(&self) -> &Id {
                match self {
                    $(Self::$variant(c) => c.issuance_id(),)+
                }
            }

            fn request_id(&self) -> &Id {
                match self {
                    $(Self::$variant(c) => c.request_id(),)+
                }
            }

            fn request(&self) -> Self::ReqVersion {
                match self {
                    $(Self::$variant(c) => {
                        let request = c.request();
                        Self::ReqVersion::$variant(request.clone())
                    })+
                }
            }

            fn public_key(&self) -> &PublicKey {
                match self {
                    $(Self::$variant(c) => c.public_key(),)+
                }
            }

            fn hierarchy_level(&self) -> HierarchyKind {
                match self {
                    Self::RootV1(_) => HierarchyKind::Root,
                    Self::IntermediateV1(_) => HierarchyKind::Intermediate,
                    Self::LeafV1(_) => HierarchyKind::Leaf,
                }
            }

            fn issue_cert(
                &self,
                request: Self::ReqVersion,
                additional_fields: IssuerAdditionalFields,
                kp: &KeyPair,
            ) -> Result<Self, IssuanceError> {
                match (self, request) {
                    (Self::RootV1(root), Self::ReqVersion::IntermediateV1(req)) => {
                        let cert = root.issue_intermediate(req, additional_fields, kp)?;
                        let version = Self::IntermediateV1(cert);
                        Ok(version)
                    }
                    (Self::IntermediateV1(intermediate), Self::ReqVersion::IntermediateV1(req)) => {
                        let cert = intermediate.issue_other_intermediate(req, additional_fields, kp)?;
                        let version = Self::IntermediateV1(cert);
                        Ok(version)
                    }
                    (Self::IntermediateV1(intermediate), Self::ReqVersion::LeafV1(req)) => {
                        let cert = intermediate.issue_leaf(req, additional_fields, kp)?;
                        let version = Self::LeafV1(cert);
                        Ok(version)
                    }
                    (_, request) => Err(IssuanceError::HierarchyError(
                        self.hierarchy_level().to_string(),
                        request.hierarchy_level().to_string(),
                    )),
                }
            }

            fn into_digest(self, role: &str, validation_failure: Option<ValidationFailure>) -> CertificateDigest{
                match self {
                    Self::RootV1(inner) => {
                        let version = format!("Root V1 {role}");
                        CertificateDigest::new(version, inner, validation_failure)
                    }
                    Self::IntermediateV1(inner) => {
                        let version = format!("Intermediate V1 {role}");
                        CertificateDigest::new(version, inner, validation_failure)
                    }
                    Self::LeafV1(inner) => {
                        let version = format!("Leaf V1 {role}");
                        CertificateDigest::new(version, inner, validation_failure)
                    }
                }
            }
        }
    }
}

impl_certificate_version_boilerplate!(
    ExemptionCertificateVersion,
    ExemptionRequestVersion,
    LeafV1,
    IntermediateV1,
    RootV1
);
impl_certificate_version_boilerplate!(
    ManufacturerCertificateVersion,
    ManufacturerRequestVersion,
    LeafV1,
    IntermediateV1,
    RootV1
);
impl_certificate_version_boilerplate!(
    InfrastructureCertificateVersion,
    InfrastructureRequestVersion,
    LeafV1,
    IntermediateV1,
    RootV1
);

impl ExemptionCertificateVersion {
    pub(crate) fn issue_elt(
        &self,
        token_request: ExemptionListTokenRequest,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
        kp: &KeyPair,
    ) -> Result<ExemptionListToken<KeyUnavailable>, IssuanceError> {
        match self {
            Self::LeafV1(c) => match token_request.version {
                ExemptionListTokenRequestVersion::V1(r) => {
                    let token = c.issue_elt(r, expiration, issuer_auth_devices, kp)?;
                    Ok(ExemptionListToken::new(ExemptionListTokenVersion::V1(
                        token,
                    )))
                }
            },
            _ => Err(IssuanceError::NonLeafIssuingToken(
                self.hierarchy_level().to_string(),
                "exemption list".to_owned(),
            )),
        }
    }

    pub(crate) fn blinding_allowed(&self) -> bool {
        match self {
            Self::RootV1(c) => c.blinding_allowed(),
            Self::IntermediateV1(c) => c.blinding_allowed(),
            Self::LeafV1(c) => c.blinding_allowed(),
        }
    }
}

impl InfrastructureCertificateVersion {
    pub(crate) fn issue_keyserver_token(
        &self,
        token_request: KeyserverTokenRequest,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<KeyserverToken<KeyUnavailable>, IssuanceError> {
        match self {
            Self::LeafV1(c) => match token_request.version {
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
            Self::LeafV1(c) => match token_request.version {
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
            Self::LeafV1(c) => match token_request.version {
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

impl ManufacturerCertificateVersion {
    pub(crate) fn issue_synthesizer_token(
        &self,
        token_request: SynthesizerTokenRequest,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<SynthesizerToken<KeyUnavailable>, IssuanceError> {
        match self {
            Self::LeafV1(c) => match token_request.version {
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

/// Each role-specific implementor of `RequestVersion` is an enum whose variants allow
/// us to deserialize a certificate request without knowing its hierarchy level or version.
pub trait RequestVersion:
    Debug + AsnType + Encode + Decode + Serialize + PartialEq + Eq + Clone
{
    type CertVersion: CertificateVersion;
    fn request_id(&self) -> &Id;
    /// Whether the certificate requests's type is root, intermediate or leaf.
    fn hierarchy_level(&self) -> HierarchyKind;
    fn public_key(&self) -> &PublicKey;
    fn into_digest(self, role: &str) -> RequestDigest;
    fn self_sign(
        self,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<Self::CertVersion, IssuanceError>;
}

/// Provides an implementation of `RequestVersion` in order to avoid boilerplate
macro_rules! impl_request_version_boilerplate {
    ($name:ident, $assoc_type:ty, $($variant:ident),+) => {
        impl RequestVersion for $name {
            type CertVersion = $assoc_type;
            fn request_id(&self) -> &Id {
                match self {
                    $(Self::$variant(c) => c.request_id(),)+
                }
            }

            fn public_key(&self) -> &PublicKey {
            match self {
                $(Self::$variant(c) => c.public_key(),)+
                }
            }

            fn hierarchy_level(&self) -> HierarchyKind {
                match self {
                    Self::RootV1(_) => HierarchyKind::Root,
                    Self::IntermediateV1(_) => HierarchyKind::Intermediate,
                    Self::LeafV1(_) => HierarchyKind::Leaf,
                }
            }

            fn into_digest(self, role: &str) -> RequestDigest {
                match self {
                    Self::RootV1(inner) => {
                        let version = format!("Root V1 {role}");
                        RequestDigest::from_version_and_request_inner(version, inner)
                    }
                    Self::IntermediateV1(inner) => {
                        let version = format!("Intermediate V1 {role}");
                        RequestDigest::from_version_and_request_inner(version, inner)
                    }
                    Self::LeafV1(inner) => {
                        let version = format!("Leaf V1 {role}");
                        RequestDigest::from_version_and_request_inner(version, inner)
                    }
                }
            }

            fn self_sign(
                self,
                additional_fields: IssuerAdditionalFields,
                kp: &KeyPair,
            ) -> Result<Self::CertVersion, IssuanceError> {
                match self {
                    Self::RootV1(root) => {
                        let inner = root.self_sign(additional_fields, kp)?;
                        Ok(Self::CertVersion::RootV1(inner))
                    }
                    _ => Err(IssuanceError::NotAbleToSelfSign(
                            self.hierarchy_level().to_string(),
                        )),
                }
            }
        }
    }
}

/// Allows exemption certificate request versioning
#[derive(Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Clone)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum ExemptionRequestVersion {
    RootV1(RequestInner<Root1, Exemption, ExemptionSubject1>),
    IntermediateV1(RequestInner<Intermediate1, Exemption, ExemptionSubject1>),
    LeafV1(RequestInner<Leaf1, Exemption, ExemptionSubject1>),
}

impl ExemptionRequestVersion {
    pub(crate) fn blinding_allowed(&self) -> bool {
        match self {
            Self::RootV1(r) => r.blinding_allowed(),
            Self::IntermediateV1(r) => r.blinding_allowed(),
            Self::LeafV1(r) => r.blinding_allowed(),
        }
    }
}

/// Allows infrastructure certificate request versioning
#[derive(Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Clone)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum InfrastructureRequestVersion {
    RootV1(RequestInner<Root1, Infrastructure, Subject1>),
    IntermediateV1(RequestInner<Intermediate1, Infrastructure, Subject1>),
    LeafV1(RequestInner<Leaf1, Infrastructure, Subject1>),
}

/// Allows manufacturer certificate request versioning
#[derive(Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Clone)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum ManufacturerRequestVersion {
    RootV1(RequestInner<Root1, Manufacturer, Subject1>),
    IntermediateV1(RequestInner<Intermediate1, Manufacturer, Subject1>),
    LeafV1(RequestInner<Leaf1, Manufacturer, Subject1>),
}

impl_request_version_boilerplate!(
    ExemptionRequestVersion,
    ExemptionCertificateVersion,
    LeafV1,
    IntermediateV1,
    RootV1
);

impl_request_version_boilerplate!(
    InfrastructureRequestVersion,
    InfrastructureCertificateVersion,
    LeafV1,
    IntermediateV1,
    RootV1
);

impl_request_version_boilerplate!(
    ManufacturerRequestVersion,
    ManufacturerCertificateVersion,
    LeafV1,
    IntermediateV1,
    RootV1
);

#[derive(Error, Debug, PartialEq)]
pub enum IssuanceError {
    #[error("a {} certificate cannot sign a {} request", .0, .1)]
    HierarchyError(String, String),
    #[error("a {} certificate cannot issue a {} token. A leaf certificate is required", .0, .1)]
    NonLeafIssuingToken(String, String),
    #[error("a {} certificate request cannot self sign", .0)]
    NotAbleToSelfSign(String),
    #[error("the ELT cannot issue the ELTR due to {0}")]
    Eltr(#[from] NonCompliantEltr),
    #[error(transparent)]
    Encode(#[from] EncodeError),
}
