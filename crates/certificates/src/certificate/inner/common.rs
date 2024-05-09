// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contains fields of the `Common` certificate data struct - these are the  fields held in common by all certificate types.
//! This includes fields establishing the identity of the certificate and the identity of the issuing certificate.

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    asn::AsnCompatible,
    keypair::PublicKey,
    shared_components::common::{
        CompatibleIdentity, ComponentVersionGuard, Description, Expiration, ExpirationError, Id,
        VersionedComponent,
    },
};

/// v1 of fields set by certificate requester
/// this should contain fields common to all cert types
#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize,
)]
#[rasn(automatic_tags)]
pub struct Subject1 {
    guard: ComponentVersionGuard<Self>,
    /// unique for each certificate request
    pub request_id: Id,
    pub pk: PublicKey,
    pub requestor_desc: Description,
    /// emails to be notified when ELTs issued by this cert are used.
    pub emails_to_notify: Vec<String>,
}

impl VersionedComponent for Subject1 {
    const COMPONENT_NAME: &'static str = "SUBJECT";
    const ITERATION: u16 = 1;
}

impl Subject1 {
    pub fn new(requestor_desc: Description, pk: PublicKey, emails_to_notify: Vec<String>) -> Self {
        let guard = ComponentVersionGuard::new();
        let request_id = Id::new_random();
        Self {
            guard,
            request_id,
            requestor_desc,
            pk,
            emails_to_notify,
        }
    }
}

impl Identity for Subject1 {
    fn to_compatible_identity(&self) -> CompatibleIdentity {
        CompatibleIdentity {
            pk: self.pk,
            desc: self.requestor_desc.to_string(),
        }
    }

    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
}

impl Subject for Subject1 {
    fn request_id(&self) -> &Id {
        &self.request_id
    }

    fn emails_to_notify(&self) -> &[String] {
        &self.emails_to_notify
    }
}

impl From<Subject1> for CompatibleIdentity {
    fn from(value: Subject1) -> Self {
        let desc = value.requestor_desc.to_string();
        CompatibleIdentity { pk: value.pk, desc }
    }
}

#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize,
)]
#[rasn(automatic_tags)]
pub struct ExemptionSubject1 {
    guard: ComponentVersionGuard<Self>,
    /// unique for each certificate request
    pub request_id: Id,
    pub pk: PublicKey,
    pub requestor_desc: Description,
    /// emails to be notified when ELTs issued by this cert are used.
    pub emails_to_notify: Vec<String>,
    pub allow_blinding: bool,
}

impl VersionedComponent for ExemptionSubject1 {
    const COMPONENT_NAME: &'static str = "EXEMPTIONSUBJECT";
    const ITERATION: u16 = 1;
}

impl ExemptionSubject1 {
    pub fn new(
        requestor_desc: Description,
        pk: PublicKey,
        emails_to_notify: Vec<String>,
        allow_blinding: bool,
    ) -> Self {
        let guard = ComponentVersionGuard::new();
        let request_id = Id::new_random();
        Self {
            guard,
            request_id,
            requestor_desc,
            pk,
            emails_to_notify,
            allow_blinding,
        }
    }
}

impl Identity for ExemptionSubject1 {
    fn to_compatible_identity(&self) -> CompatibleIdentity {
        CompatibleIdentity {
            pk: self.pk,
            desc: self.requestor_desc.to_string(),
        }
    }

    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
}

impl Subject for ExemptionSubject1 {
    fn request_id(&self) -> &Id {
        &self.request_id
    }

    fn emails_to_notify(&self) -> &[String] {
        &self.emails_to_notify
    }
}

impl From<ExemptionSubject1> for CompatibleIdentity {
    fn from(value: ExemptionSubject1) -> Self {
        let desc = value.requestor_desc.to_string();
        CompatibleIdentity { pk: value.pk, desc }
    }
}

/// fields set by certificate issuer
#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[rasn(automatic_tags)]
pub struct Issuer1 {
    guard: ComponentVersionGuard<Self>,
    pub issuance_id: Id,
    pub identity: CompatibleIdentity,
    pub expiration: Expiration,
    /// emails to be notified when ELTs issued by this cert are used (set by issuer).
    pub additional_emails_to_notify: Vec<String>,
}

/// Contains fields to be supplied on issuance that cannot be derived from the issuer's own certificate.
#[derive(Debug, Default)]
pub struct IssuerAdditionalFields {
    pub expiration: Expiration,
    /// emails to be notified when ELTs issued by this cert are used (set by issuer).
    pub emails_to_notify: Vec<String>,
}

impl IssuerAdditionalFields {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_expiry_in_days(mut self, days: i64) -> Result<Self, ExpirationError> {
        self.expiration = Expiration::expiring_in_days(days)?;
        Ok(self)
    }

    pub fn with_emails_to_notify<T: Into<String>>(
        mut self,
        emails: impl IntoIterator<Item = T>,
    ) -> Self {
        self.emails_to_notify
            .extend(emails.into_iter().map(|x| x.into()));
        self
    }
}

impl Issuer1 {
    pub fn new(identity: CompatibleIdentity, additional_fields: IssuerAdditionalFields) -> Self {
        let guard = ComponentVersionGuard::new();
        let issuance_id = Id::new_random();
        Self {
            guard,
            issuance_id,
            identity,
            expiration: additional_fields.expiration,
            additional_emails_to_notify: additional_fields.emails_to_notify,
        }
    }
}

impl VersionedComponent for Issuer1 {
    const COMPONENT_NAME: &'static str = "ISSUER";
    const ITERATION: u16 = 1;
}

impl Identity for Issuer1 {
    fn to_compatible_identity(&self) -> CompatibleIdentity {
        self.identity.clone()
    }

    fn public_key(&self) -> &PublicKey {
        &self.identity.pk
    }
}

impl Issuer for Issuer1 {
    fn expiration(&self) -> &Expiration {
        &self.expiration
    }

    fn issuance_id(&self) -> &Id {
        &self.issuance_id
    }

    fn issuer_description(&self) -> &str {
        &self.identity.desc
    }

    fn additional_emails_to_notify(&self) -> &[String] {
        &self.additional_emails_to_notify
    }
}

/// Holds the common certificate fields for all cert types.
///
/// The subject field contains information related to the certificate identity.
/// It originates in the certificate request.
///
/// The issuer and expiration fields are added by the certificate issuer.
#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[rasn(automatic_tags)]
pub struct Common<S, I> {
    /// fields set by certificate requestor
    pub subject: S,
    /// fields set by certificate issuer
    pub issuer: I,
}

pub trait Identity: Clone + PartialEq + Eq + AsnCompatible {
    fn to_compatible_identity(&self) -> CompatibleIdentity;
    fn public_key(&self) -> &PublicKey;
}

/// Functionality that we expect to be available on issuer supplied fields of all certificate versions.
pub trait Issuer: Identity {
    fn expiration(&self) -> &Expiration;
    /// Unique for each certificate
    fn issuance_id(&self) -> &Id;
    fn issuer_description(&self) -> &str;
    fn additional_emails_to_notify(&self) -> &[String];
}

/// Functionality that we expect to be available on all certificate request versions.
pub trait Subject: Identity {
    /// Unique for each certificate request
    fn request_id(&self) -> &Id;
    fn emails_to_notify(&self) -> &[String];
}
