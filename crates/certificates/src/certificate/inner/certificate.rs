// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module defines functionality available for issued certificates.
//! This module contains the inner certificate structure which is elsewhere wrapped in a version enum to create a `Certificate`.
//! A `CertificateInner` is able to sign a `RequestInner` to issue another `CertificateInner`.

use std::marker::PhantomData;

use rasn::{types::*, Decode, Encode};
use serde::Serialize;

use crate::{
    asn::ToASN1DerBytes,
    error::EncodeError,
    keypair::{PublicKey, Signature},
    shared_components::{
        common::{Expiration, Id, Signed},
        role::{Exemption, Infrastructure, Role, RoleGuard},
    },
    tokens::{
        exemption::{
            authenticator::Authenticator,
            et::{ExemptionTokenIssuer1, ExemptionTokenRequest1},
        },
        infrastructure::{
            database::{DatabaseTokenIssuer1, DatabaseTokenRequest1},
            hlt::{HltTokenIssuer1, HltTokenRequest1},
            keyserver::{KeyserverTokenIssuer1, KeyserverTokenRequest1},
        },
        manufacturer::synthesizer::{SynthesizerTokenIssuer1, SynthesizerTokenRequest1},
        TokenData,
    },
    utility::combine_and_dedup_items,
    Description, KeyPair, Manufacturer,
};

use super::{
    common::{Common, Issuer, Issuer1, IssuerAdditionalFields, Subject},
    hierarchy::{HierarchyLevel, Intermediate, Leaf, Root},
    request::RequestInner,
    ExemptionSubject1,
};

/// Contains the data that is held by a certificate, including fields added by the certificate issuer.
/// This is the data that will be signed by the certificate issuer.
///
/// `cert_type` holds the fields specific to the certificate type.
///
/// `common` holds the fields common to all certificate types.
#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize,
)]
#[rasn(automatic_tags)]
pub struct CertificateData<T, R, S, I>
where
    R: Role,
{
    pub(crate) hierarchy_level: T,
    pub(crate) role: RoleGuard<R>,
    pub(crate) common: Common<S, I>,
}

impl<T, R, S, I> CertificateData<T, R, S, I>
where
    R: Role,
{
    pub fn new(hierarchy_level: T, common: Common<S, I>) -> Self {
        Self {
            hierarchy_level,
            role: RoleGuard(PhantomData::<R>),
            common,
        }
    }
}

#[derive(
    Debug, AsnType, Encode, Decode, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord, Clone,
)]
pub struct CertificateInner<T, R, S, I>(pub(crate) Signed<CertificateData<T, R, S, I>>)
where
    R: Role;

impl<T, R, S, I> CertificateInner<T, R, S, I>
where
    T: HierarchyLevel,
    R: Role,
    S: Subject,
    I: Issuer,
{
    pub(crate) fn new(signed_data: Signed<CertificateData<T, R, S, I>>) -> Self {
        Self(signed_data)
    }

    pub fn public_key(&self) -> &PublicKey {
        self.0.data.common.subject.public_key()
    }
    pub fn request_id(&self) -> &Id {
        self.0.data.common.subject.request_id()
    }
    pub fn issuance_id(&self) -> &Id {
        self.0.data.common.issuer.issuance_id()
    }
    pub fn signature(&self) -> &Signature {
        &self.0.signature
    }
    pub fn data(&self) -> Result<Vec<u8>, EncodeError> {
        self.0.data.to_der()
    }
    pub(crate) fn issuer_public_key(&self) -> &PublicKey {
        self.0.data.common.issuer.public_key()
    }

    pub(crate) fn issuer_description(&self) -> &str {
        self.0.data.common.issuer.issuer_description()
    }

    pub(crate) fn requestor_description(&self) -> &Description {
        self.0.data.common.subject.requestor_description()
    }

    pub(crate) fn expiration(&self) -> &Expiration {
        self.0.data.common.issuer.expiration()
    }

    pub(crate) fn request(&self) -> RequestInner<T, R, S> {
        RequestInner::new(self.0.data.common.subject.clone())
    }
}

impl<T, R, S1, I1> CertificateInner<T, R, S1, I1>
where
    T: HierarchyLevel,
    R: Role,
    S1: Subject,
{
    /// A new certificate is created from a certificate request and
    /// the additional fields added by the issuing certificate.
    /// The new certificate's version is determined by the version of
    /// the certificate request supplied.
    /// If we want to issue certs with different issuer fields we will have to create
    /// an `Issuer2` struct and add a corresponding `issue_cert` function here and
    /// in inner/request (for self signing).
    fn issue_cert<M: HierarchyLevel, S2: Subject>(
        &self,
        req: RequestInner<M, R, S2>,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<CertificateInner<M, R, S2, Issuer1>, EncodeError> {
        let issuer_identity = self.0.data.common.subject.to_compatible_identity();
        let issuer = Issuer1::new(issuer_identity, additional_fields);

        let common = Common {
            subject: req.subject,
            issuer,
        };

        let data = CertificateData {
            hierarchy_level: req.hierarchy_level,
            role: RoleGuard(PhantomData::<R>),
            common,
        };
        let signed_data = kp.sign_asn_encodable_data(data)?;
        Ok(CertificateInner(signed_data))
    }
}

impl<T, R, S1, I1> CertificateInner<T, R, S1, I1>
where
    T: Root,
    R: Role,
    S1: Subject,
{
    pub fn issue_intermediate<M: Intermediate, S2: Subject>(
        &self,
        intermediate: RequestInner<M, R, S2>,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<CertificateInner<M, R, S2, Issuer1>, EncodeError> {
        self.issue_cert(intermediate, additional_fields, kp)
    }
}

impl<T, R, S1, I1> CertificateInner<T, R, S1, I1>
where
    T: Intermediate,
    R: Role,
    S1: Subject,
{
    pub fn issue_other_intermediate<M: Intermediate, S2: Subject>(
        &self,
        intermediate: RequestInner<M, R, S2>,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<CertificateInner<M, R, S2, Issuer1>, EncodeError> {
        self.issue_cert(intermediate, additional_fields, kp)
    }
    pub fn issue_leaf<M: Leaf, S2: Subject>(
        &self,
        intermediate: RequestInner<M, R, S2>,
        additional_fields: IssuerAdditionalFields,
        kp: &KeyPair,
    ) -> Result<CertificateInner<M, R, S2, Issuer1>, EncodeError> {
        self.issue_cert(intermediate, additional_fields, kp)
    }
}

impl<T, S, I> CertificateInner<T, Exemption, S, I>
where
    T: Leaf,
    S: Subject,
    I: Issuer,
{
    /// An exemption token is created from a exemption token request and
    /// the additional fields are added by the issuing certificate.
    pub(crate) fn issue_exemption_token(
        &self,
        request: ExemptionTokenRequest1,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
        kp: &KeyPair,
    ) -> Result<Signed<TokenData<ExemptionTokenRequest1, ExemptionTokenIssuer1>>, EncodeError> {
        let issuer = self.0.data.common.subject.to_compatible_identity();

        let notify_emails = self.0.data.common.subject.emails_to_notify();
        let additional_notify_emails = self.0.data.common.issuer.additional_emails_to_notify();
        let emails_to_notify = combine_and_dedup_items(notify_emails, additional_notify_emails);

        let issuer_fields =
            ExemptionTokenIssuer1::new(issuer, expiration, issuer_auth_devices, emails_to_notify);

        let et = TokenData {
            request,
            issuer_fields,
        };
        kp.sign_asn_encodable_data(et)
    }
}

impl<T, I> CertificateInner<T, Exemption, ExemptionSubject1, I>
where
    I: Issuer,
{
    pub(crate) fn blinding_allowed(&self) -> bool {
        self.0.data.common.subject.allow_blinding
    }
}

impl<T, S, I> CertificateInner<T, Infrastructure, S, I>
where
    T: Leaf,
    S: Subject,
    I: Issuer,
{
    pub(crate) fn issue_keyserver_token(
        &self,
        request: KeyserverTokenRequest1,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<Signed<TokenData<KeyserverTokenRequest1, KeyserverTokenIssuer1>>, EncodeError> {
        let issuer = self.0.data.common.subject.to_compatible_identity();

        let issuer_fields = KeyserverTokenIssuer1::new(issuer, expiration);

        let kt = TokenData {
            request,
            issuer_fields,
        };
        kp.sign_asn_encodable_data(kt)
    }

    pub(crate) fn issue_database_token(
        &self,
        request: DatabaseTokenRequest1,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<Signed<TokenData<DatabaseTokenRequest1, DatabaseTokenIssuer1>>, EncodeError> {
        let issuer = self.0.data.common.subject.to_compatible_identity();

        let issuer_fields = DatabaseTokenIssuer1::new(issuer, expiration);

        let kt = TokenData {
            request,
            issuer_fields,
        };
        kp.sign_asn_encodable_data(kt)
    }

    pub(crate) fn issue_hlt_token(
        &self,
        request: HltTokenRequest1,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<Signed<TokenData<HltTokenRequest1, HltTokenIssuer1>>, EncodeError> {
        let issuer = self.0.data.common.subject.to_compatible_identity();

        let issuer_fields = HltTokenIssuer1::new(issuer, expiration);

        let kt = TokenData {
            request,
            issuer_fields,
        };
        kp.sign_asn_encodable_data(kt)
    }
}

impl<T, S, I> CertificateInner<T, Manufacturer, S, I>
where
    T: Leaf,
    S: Subject,
    I: Issuer,
{
    pub(crate) fn issue_synthesizer_token(
        &self,
        request: SynthesizerTokenRequest1,
        expiration: Expiration,
        kp: &KeyPair,
    ) -> Result<Signed<TokenData<SynthesizerTokenRequest1, SynthesizerTokenIssuer1>>, EncodeError>
    {
        let issuer = self.0.data.common.subject.to_compatible_identity();

        let issuer_fields = SynthesizerTokenIssuer1::new(issuer, expiration);

        let kt = TokenData {
            request,
            issuer_fields,
        };
        kp.sign_asn_encodable_data(kt)
    }
}
