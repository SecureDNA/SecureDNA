// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use std::marker::PhantomData;

use crate::{
    asn::ToASN1DerBytes,
    error::EncodeError,
    keypair::{KeyPair, PublicKey},
    shared_components::{
        common::{Id, Signed},
        role::{Role, RoleGuard},
    },
    Exemption,
};
use rasn::{types::*, Decode, Encode};

use super::{
    common::{Common, Issuer1, IssuerAdditionalFields, Subject},
    hierarchy::{HierarchyLevel, Root},
    CertificateData, CertificateInner, ExemptionSubject1,
};

/// Certificate request, only contains certificate fields that are provided by the certificate subject.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize)]
#[rasn(automatic_tags)]
pub struct RequestInner<T, R, S>
where
    T: HierarchyLevel,
    R: Role,
    S: Subject,
{
    pub hierarchy_level: T,
    pub role: RoleGuard<R>,
    pub subject: S,
}

impl<T, R, S> RequestInner<T, R, S>
where
    T: HierarchyLevel,
    R: Role,
    S: Subject,
{
    pub fn new(subject: S) -> Self {
        Self {
            hierarchy_level: T::new(),
            role: RoleGuard(PhantomData::<R>),
            subject,
        }
    }
    pub fn request_id(&self) -> &Id {
        self.subject.request_id()
    }
    pub fn public_key(&self) -> &PublicKey {
        self.subject.public_key()
    }
}

impl<T, R, S> RequestInner<T, R, S>
where
    T: Root,
    R: Role,
    S: Subject,
{
    pub(crate) fn self_sign(
        self,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<CertificateInner<T, R, S, Issuer1>, EncodeError> {
        let issuer_identity = self.subject.to_compatible_identity();
        let issuer = Issuer1::new(issuer_identity, additional_fields);
        let common = Common {
            subject: self.subject,
            issuer,
        };
        let data = CertificateData::new(self.hierarchy_level, common);
        let der_bytes = &data.to_der()?;
        let signature = kp.sign(der_bytes);
        let fields = Signed::new(data, signature);
        Ok(CertificateInner::new(fields))
    }
}

impl<T: HierarchyLevel> RequestInner<T, Exemption, ExemptionSubject1> {
    pub(crate) fn blinding_allowed(&self) -> bool {
        self.subject.allow_blinding
    }
}
