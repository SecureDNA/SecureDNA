// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use std::marker::PhantomData;

use crate::{
    asn::ToASN1DerBytes,
    error::EncodeError,
    keypair::{KeyPair, PublicKey},
    shared_components::{
        common::{Description, Id, Signed},
        role::{Role, RoleGuard},
    },
};
use rasn::{types::*, Decode, Encode};

use super::{
    common::{Common, Issuer1, IssuerAdditionalFields, Subject, Subject1},
    hierarchy::{HierarchyLevel, Root},
    CertificateData, CertificateInner,
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

pub struct RequestBuilderInner<T, R>
where
    T: HierarchyLevel,
{
    public_key: PublicKey,
    description: Option<Description>,
    emails_to_notify: Vec<String>,
    hierarchy: T,
    role: PhantomData<R>,
}

impl<T, R> RequestBuilderInner<T, R>
where
    T: HierarchyLevel,
{
    pub fn new(hierarchy: T, public_key: PublicKey) -> Self {
        RequestBuilderInner {
            public_key,
            description: None,
            hierarchy,
            role: PhantomData::<R>,
            emails_to_notify: vec![],
        }
    }

    pub fn with_description(mut self, desc: Description) -> Self {
        self.description = Some(desc);
        self
    }

    pub fn with_emails_to_notify<S: Into<String>>(
        mut self,
        emails: impl IntoIterator<Item = S>,
    ) -> Self {
        self.emails_to_notify = emails.into_iter().map(|x| x.into()).collect();
        self
    }

    pub fn build(self) -> RequestInner<T, R, Subject1>
    where
        R: Role,
    {
        let desc = self.description.unwrap_or_default();
        let identity = Subject1::new(desc, self.public_key, self.emails_to_notify);

        RequestInner {
            hierarchy_level: self.hierarchy,
            role: RoleGuard(PhantomData::<R>),
            subject: identity,
        }
    }
}
