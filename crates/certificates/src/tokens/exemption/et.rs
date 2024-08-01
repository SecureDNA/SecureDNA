// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating an `ExemptionTokenRequest`.
//! A `Certificate` is able to sign a `ExemptionTokenRequest` to issue a `ExemptionToken`.

use std::fmt::Display;

use quickdna::{DnaSequence, NucleotideAmbiguous};
use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chain::Chain;
use crate::{
    asn::ToASN1DerBytes,
    error::EncodeError,
    impl_boilerplate_for_token, impl_boilerplate_for_token_request,
    impl_boilerplate_for_token_request_version, impl_boilerplate_for_token_version,
    impl_encoding_boilerplate,
    issued::Issued,
    keypair::{PublicKey, Signature},
    pem::PemTaggable,
    shared_components::{
        common::{
            CompatibleIdentity, ComponentVersionGuard, Description, Expiration, Id, Signed,
            VersionedComponent,
        },
        role::Exemption,
    },
    tokens::{TokenData, TokenGroup},
    IssuanceError, KeyAvailable, KeyMismatchError, KeyPair, KeyUnavailable,
};
use crate::{Digestible, TokenKind};

use super::digest::{ExemptionTokenDigest, ExemptionTokenRequestDigest};
use super::{authenticator::Authenticator, organism::Organism};

// tsgen
pub type ShippingAddress = Vec<String>;

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
// tsgen
#[rasn(automatic_tags)]
pub(crate) struct ExemptionTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    /// unique for each token
    pub(crate) request_id: Id,
    pub(crate) public_key: Option<PublicKey>,
    pub(crate) exemptions: Vec<Organism>,
    pub(crate) requestor: Description,
    pub(crate) requestor_auth_devices: Vec<Authenticator>,
    pub(crate) shipping_addresses: Vec<ShippingAddress>,
}

impl ExemptionTokenRequest1 {
    fn new(
        public_key: Option<PublicKey>,
        exemptions: Vec<Organism>,
        requestor: Description,
        requestor_auth_devices: Vec<Authenticator>,
        shipping_addresses: Vec<ShippingAddress>,
    ) -> Self {
        let guard = ComponentVersionGuard::new();
        let request_id = Id::new_random();
        Self {
            guard,
            request_id,
            public_key,
            exemptions,
            requestor,
            requestor_auth_devices,
            shipping_addresses,
        }
    }
}
impl VersionedComponent for ExemptionTokenRequest1 {
    const COMPONENT_NAME: &'static str = "ETR";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all exemption token request versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// tsgen
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum ExemptionTokenRequestVersion {
    V1(ExemptionTokenRequest1),
}

impl ExemptionTokenRequestVersion {
    pub(crate) fn exemptions(&self) -> &[Organism] {
        match self {
            Self::V1(r) => &r.exemptions,
        }
    }

    pub(crate) fn shipping_addresses(&self) -> &[ShippingAddress] {
        match self {
            Self::V1(r) => &r.shipping_addresses,
        }
    }

    pub(crate) fn requestor_auth_devices(&self) -> &[Authenticator] {
        match self {
            Self::V1(r) => &r.requestor_auth_devices,
        }
    }

    pub(crate) fn try_public_key(&self) -> Option<&PublicKey> {
        match self {
            Self::V1(r) => r.public_key.as_ref(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
// tsgen
pub struct ExemptionTokenRequest {
    pub(crate) version: ExemptionTokenRequestVersion,
}

impl ExemptionTokenRequest {
    pub(crate) fn new(version: ExemptionTokenRequestVersion) -> Self {
        Self { version }
    }

    pub fn v1_token_request(
        public_key: Option<PublicKey>,
        exemptions: Vec<Organism>,
        requestor: Description,
        requestor_auth_devices: Vec<Authenticator>,
        shipping_addresses: Vec<ShippingAddress>,
    ) -> Self {
        let request = ExemptionTokenRequest1::new(
            public_key,
            exemptions,
            requestor,
            requestor_auth_devices,
            shipping_addresses,
        );
        let version = ExemptionTokenRequestVersion::V1(request);
        ExemptionTokenRequest::new(version)
    }

    pub fn exemptions(&self) -> &[Organism] {
        self.version.exemptions()
    }

    pub fn shipping_addresses(&self) -> &[ShippingAddress] {
        self.version.shipping_addresses()
    }

    pub fn requestor_auth_devices(&self) -> &[Authenticator] {
        self.version.requestor_auth_devices()
    }

    pub fn try_public_key(&self) -> Option<&PublicKey> {
        self.version.try_public_key()
    }
}

impl Digestible for ExemptionTokenRequest {
    type Digest = ExemptionTokenRequestDigest;
}

impl PemTaggable for ExemptionTokenRequest {
    fn tag() -> String {
        "SECUREDNA EXEMPTION TOKEN REQUEST".to_string()
    }
}

impl Decode for ExemptionTokenRequest {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = ExemptionTokenRequestVersion::decode_with_tag_and_constraints(
            decoder,
            tag,
            constraints,
        )?;
        Ok(ExemptionTokenRequest::new(version))
    }
}

/// Data that will be signed by the issuer of the exemption token
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
// tsgen
#[rasn(automatic_tags)]
pub(crate) struct ExemptionTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    pub(crate) issuance_id: Id,
    pub(crate) identity: CompatibleIdentity,
    pub(crate) expiration: Expiration,
    pub(crate) issuer_auth_devices: Vec<Authenticator>,
    pub(crate) emails_to_notify: Vec<String>,
}

impl ExemptionTokenIssuer1 {
    pub(crate) fn new(
        identity: CompatibleIdentity,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
        emails_to_notify: Vec<String>,
    ) -> Self {
        let guard = ComponentVersionGuard::new();
        let issuance_id = Id::new_random();
        Self {
            guard,
            issuance_id,
            identity,
            expiration,
            issuer_auth_devices,
            emails_to_notify,
        }
    }
}

impl VersionedComponent for ExemptionTokenIssuer1 {
    const COMPONENT_NAME: &'static str = "ELTI";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all exemption token versions.
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
// tsgen
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum ExemptionTokenVersion {
    V1(Signed<TokenData<ExemptionTokenRequest1, ExemptionTokenIssuer1>>),
}

impl ExemptionTokenVersion {
    pub(crate) fn requestor_description(&self) -> &Description {
        match self {
            Self::V1(c) => &c.data.request.requestor,
        }
    }

    pub(crate) fn requestor_auth_devices(&self) -> &[Authenticator] {
        match self {
            Self::V1(c) => &c.data.request.requestor_auth_devices,
        }
    }

    pub(crate) fn issuer_auth_devices(&self) -> &[Authenticator] {
        match self {
            Self::V1(c) => &c.data.issuer_fields.issuer_auth_devices,
        }
    }

    pub(crate) fn exemptions(&self) -> &[Organism] {
        match self {
            Self::V1(c) => &c.data.request.exemptions,
        }
    }

    pub(crate) fn emails_to_notify(&self) -> &[String] {
        match self {
            Self::V1(c) => &c.data.issuer_fields.emails_to_notify,
        }
    }

    pub(crate) fn try_public_key(&self) -> Option<&PublicKey> {
        match self {
            Self::V1(c) => c.data.request.public_key.as_ref(),
        }
    }

    pub(crate) fn shipping_addresses(&self) -> &[ShippingAddress] {
        match self {
            Self::V1(c) => &c.data.request.shipping_addresses,
        }
    }

    pub(crate) fn issue_exemption_token(
        &self,
        request: ExemptionTokenRequest,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
        kp: &KeyPair,
    ) -> Result<Self, IssuanceError> {
        match (self, request.version) {
            (Self::V1(t), ExemptionTokenRequestVersion::V1(request)) => {
                let issuer = CompatibleIdentity {
                    pk: kp.public_key(),
                    desc: t.data.request.requestor.to_string(),
                };

                let mut emails_to_notify = self.emails_to_notify().to_owned();
                if let Some(email) = &t.data.request.requestor.email {
                    emails_to_notify.push(email.clone());
                }

                let mut issuer_auth_devices = issuer_auth_devices;
                for device in self.issuer_auth_devices() {
                    if !issuer_auth_devices.contains(device) {
                        issuer_auth_devices.push(device.clone());
                    }
                }

                let signed_data = issue_exemption_token_v1_with_keypair(
                    request,
                    issuer,
                    emails_to_notify,
                    expiration,
                    issuer_auth_devices,
                    kp,
                )?;
                Ok(Self::V1(signed_data))
            }
        }
    }

    pub(crate) fn request(&self) -> ExemptionTokenRequestVersion {
        match self {
            ExemptionTokenVersion::V1(t) => {
                ExemptionTokenRequestVersion::V1(t.data.request.clone())
            }
        }
    }
}

fn issue_exemption_token_v1_with_keypair(
    request: ExemptionTokenRequest1,
    issuer: CompatibleIdentity,
    emails_to_notify: Vec<String>,
    expiration: Expiration,
    issuer_auth_devices: Vec<Authenticator>,
    keypair: &KeyPair,
) -> Result<Signed<TokenData<ExemptionTokenRequest1, ExemptionTokenIssuer1>>, EncodeError> {
    let issuer_fields =
        ExemptionTokenIssuer1::new(issuer, expiration, issuer_auth_devices, emails_to_notify);

    let et = TokenData {
        request,
        issuer_fields,
    };
    keypair.sign_asn_encodable_data(et)
}

/// Token to allow the synthesis of restricted hazards
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
// tsgen
pub struct ExemptionToken<K> {
    pub(crate) version: ExemptionTokenVersion,
    key_state: K,
}

impl<K> ExemptionToken<K> {
    pub fn requestor_description(&self) -> &Description {
        self.version.requestor_description()
    }

    pub fn requestor_auth_devices(&self) -> &[Authenticator] {
        self.version.requestor_auth_devices()
    }

    pub fn issuer_auth_devices(&self) -> &[Authenticator] {
        self.version.issuer_auth_devices()
    }

    pub fn exemptions(&self) -> &[Organism] {
        self.version.exemptions()
    }

    pub fn emails_to_notify(&self) -> &[String] {
        self.version.emails_to_notify()
    }

    pub fn has_dna_sequences(&self) -> bool {
        self.exemptions().iter().any(Organism::has_dna_sequences)
    }

    pub fn dna_sequences(&self) -> impl Iterator<Item = &DnaSequence<NucleotideAmbiguous>> {
        self.exemptions().iter().flat_map(Organism::dna_sequences)
    }

    pub fn try_public_key(&self) -> Option<&PublicKey> {
        self.version.try_public_key()
    }

    pub fn shipping_addresses(&self) -> &[ShippingAddress] {
        self.version.shipping_addresses()
    }

    pub fn request(&self) -> ExemptionTokenRequest {
        ExemptionTokenRequest::new(self.version.request())
    }

    /// Whether the child exemption token's issuance complies with all requirements
    pub fn check_issuance_constraints(
        &self,
        child_et: &ExemptionToken<KeyUnavailable>,
    ) -> Result<(), IssuanceError> {
        let mut causes = vec![];
        if let Err(e) = self.check_ability_to_issue(&child_et.request()) {
            causes.extend(e.causes);
        }

        // All parent exemption token 'emails to notify' should appear in child exemption token
        if !self
            .emails_to_notify()
            .iter()
            .all(|email| child_et.emails_to_notify().contains(email))
        {
            causes.push(NonComplianceCause::Email);
        }

        // All parent 'issuer auth devices' should appear in child exemption token
        if !self
            .issuer_auth_devices()
            .iter()
            .all(|device| child_et.issuer_auth_devices().contains(device))
        {
            causes.push(NonComplianceCause::IssuerAuthDevices);
        }
        if !causes.is_empty() {
            return Err(NonCompliantChildToken { causes }.into());
        }
        Ok(())
    }

    /// Whether this exemption token request fulfills the necessary requirements in order to be issued by the exemption token
    pub fn check_ability_to_issue(
        &self,
        etr: &ExemptionTokenRequest,
    ) -> Result<(), NonCompliantChildToken> {
        let mut causes = vec![];
        // We can't allow a child token to contain exemptions
        // that are not on the parent
        for organism in etr.exemptions() {
            if !self.exemptions().contains(organism) {
                causes.push(NonComplianceCause::Exemptions);
            }
        }
        // We can't allow a child token to contain shipping addresses
        // that are not on the parent
        for address in etr.shipping_addresses() {
            if !self.shipping_addresses().contains(address) {
                causes.push(NonComplianceCause::ShippingAddress);
            }
        }
        // We don't want to allow child tokens which can issue further tokens
        if etr.try_public_key().is_some() {
            causes.push(NonComplianceCause::AssociatedKeyNotAllowed);
        }
        if !causes.is_empty() {
            return Err(NonCompliantChildToken { causes });
        }
        Ok(())
    }
}

impl<K> Digestible for ExemptionToken<K> {
    type Digest = ExemptionTokenDigest;
}

impl ExemptionToken<KeyUnavailable> {
    pub(crate) fn new(version: ExemptionTokenVersion) -> Self {
        Self {
            version,
            key_state: KeyUnavailable,
        }
    }
    pub fn load_key(
        self,
        keypair: KeyPair,
    ) -> Result<ExemptionToken<KeyAvailable>, EtLoadKeyError> {
        match self.try_public_key() {
            None => Err(EtLoadKeyError::NoAssociatedKey),
            Some(public_key) => {
                let key_state = KeyUnavailable::load_key(keypair, public_key)?;
                Ok(ExemptionToken {
                    version: self.version,
                    key_state,
                })
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum EtLoadKeyError {
    #[error(transparent)]
    Mismatch(#[from] KeyMismatchError),
    #[error("The exemption token does not have an associated keypair")]
    NoAssociatedKey,
}

#[derive(Error, Debug, PartialEq)]
pub struct NonCompliantChildToken {
    pub causes: Vec<NonComplianceCause>,
}

impl Display for NonCompliantChildToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut items_iter = self.causes.iter().peekable();
        while let Some(item) = items_iter.next() {
            write!(f, "{}", item)?;
            if items_iter.peek().is_some() {
                writeln!(f, "\n")?;
            }
        }
        Ok(())
    }
}

#[derive(Error, Debug, PartialEq, Serialize)]
// tsgen
pub enum NonComplianceCause {
    #[error(
        "The child token does not contain all the 'emails to notify' found on the issuing token"
    )]
    Email,
    #[error("The exemptions on the child token are not a subset of those on the issuer")]
    Exemptions,
    #[error("The shipping addresses on the child token are not a subset of those on the issuer")]
    ShippingAddress,
    #[error("A child exemption token cannot have an associated keypair")]
    AssociatedKeyNotAllowed,
    #[error(
        "The child token does not contain all the authentication devices specified by the issuer of the parent token"
    )]
    IssuerAuthDevices,
}

impl ExemptionToken<KeyAvailable> {
    pub fn issue_exemption_token(
        &self,
        etr: ExemptionTokenRequest,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
    ) -> Result<ExemptionToken<KeyUnavailable>, IssuanceError> {
        self.check_ability_to_issue(&etr)?;
        let et_version = self.version.issue_exemption_token(
            etr,
            expiration,
            issuer_auth_devices,
            self.key_state.kp(),
        )?;
        Ok(ExemptionToken::new(et_version))
    }
}

impl<K> PemTaggable for ExemptionToken<K> {
    fn tag() -> String {
        "SECUREDNA EXEMPTION TOKEN".to_string()
    }
}

impl Decode for ExemptionToken<KeyUnavailable> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version =
            ExemptionTokenVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(ExemptionToken::new(version))
    }
}

/// Related types for ExemptionToken
#[derive(AsnType, Clone, Encode, Decode, Debug)]
pub struct ExemptionTokenGroup;

impl TokenGroup for ExemptionTokenGroup {
    type AssociatedRole = Exemption;
    type TokenRequest = ExemptionTokenRequest;
    type Token = ExemptionToken<KeyUnavailable>;
    type ChainType = Chain<Self::AssociatedRole>;

    fn token_kind() -> TokenKind {
        TokenKind::Exemption
    }
}

impl_boilerplate_for_token_request_version! {ExemptionTokenRequestVersion, V1}
impl_boilerplate_for_token_request! {ExemptionTokenRequest}
impl_encoding_boilerplate! {ExemptionTokenRequest}

impl_boilerplate_for_token_version! {ExemptionTokenVersion, V1}
impl_boilerplate_for_token! {ExemptionToken<K>}
impl_encoding_boilerplate! {ExemptionToken<K>}

#[cfg(test)]
pub fn issue_exemption_token_without_compliance_check(
    etr: ExemptionTokenRequest,
    kp: &KeyPair,
    emails_to_notify: Vec<String>,
    issuer_auth_devices: Vec<Authenticator>,
) -> ExemptionToken<KeyUnavailable> {
    match etr.version {
        ExemptionTokenRequestVersion::V1(v1) => {
            let issuer_identity = CompatibleIdentity {
                pk: kp.public_key(),
                desc: String::new(),
            };
            let inner = issue_exemption_token_v1_with_keypair(
                v1,
                issuer_identity,
                emails_to_notify,
                Expiration::default(),
                issuer_auth_devices,
                kp,
            )
            .unwrap();
            ExemptionToken::new(ExemptionTokenVersion::V1(inner))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::{create_etr_with_options, create_issuing_exemption_token_bundle};
    use crate::tokens::exemption::et::{NonComplianceCause, NonCompliantChildToken};
    use crate::{
        test_helpers::{create_etr, create_exemptions, create_leaf_cert},
        Description, Exemption, ExemptionToken, ExemptionTokenRequest, Expiration, GenbankId,
        IssuanceError, KeyPair, Organism, PemDecodable, PemEncodable, Sequence, SequenceIdentifier,
    };

    #[test]
    fn can_issue_exemption_token() {
        let cert = create_leaf_cert::<Exemption>();
        let request = create_etr(create_exemptions());
        cert.issue_exemption_token(request, Expiration::default(), vec![])
            .unwrap();
    }

    #[test]
    fn can_serialise_etr_to_pem() {
        let etr = create_etr(create_exemptions());
        let encoded = etr.to_pem().unwrap();
        let etr_decoded = ExemptionTokenRequest::from_pem(encoded).unwrap();
        assert_eq!(etr, etr_decoded);
    }

    #[test]
    fn can_serialise_et_to_pem() {
        let leaf_cert = create_leaf_cert::<Exemption>();
        let etr = create_etr(create_exemptions());

        let issuer_auth_devices = Vec::new();

        let et = leaf_cert
            .issue_exemption_token(
                etr,
                Expiration::expiring_in_days(90).unwrap(),
                issuer_auth_devices,
            )
            .unwrap();

        let encoded = et.to_pem().unwrap();
        let et_decoded = ExemptionToken::from_pem(encoded).unwrap();

        assert_eq!(et, et_decoded);
    }

    #[test]
    fn can_issue_et_from_et() {
        let (et_bundle, et_kp, _) = create_issuing_exemption_token_bundle();

        let child_etr = create_etr_with_options(None, vec![], vec![]);
        et_bundle
            .token
            .clone()
            .load_key(et_kp)
            .unwrap()
            .issue_exemption_token(child_etr, Expiration::default(), vec![])
            .expect("et should have been able to issue a further et");
    }

    #[test]
    fn cannot_issue_child_et_with_associated_key() {
        let (et_bundle, et_kp, _) = create_issuing_exemption_token_bundle();

        let child_kp = KeyPair::new_random();
        let child_etr = create_etr_with_options(Some(child_kp.public_key()), vec![], vec![]);

        let err = et_bundle
            .token
            .clone()
            .load_key(et_kp)
            .unwrap()
            .issue_exemption_token(child_etr, Expiration::default(), vec![])
            .expect_err("et should not have been issued");

        assert_eq!(
            err,
            IssuanceError::Etr(NonCompliantChildToken {
                causes: vec![NonComplianceCause::AssociatedKeyNotAllowed],
            })
        )
    }

    #[test]
    fn cannot_issue_et_with_shipping_address_not_present_on_issuing_et() {
        let (et_bundle, et_kp, _) = create_issuing_exemption_token_bundle();

        let shipping_address = vec!["22 New Street".to_string(), "Some Other City".to_string()];
        let etr = ExemptionTokenRequest::v1_token_request(
            None,
            vec![],
            Description::default(),
            vec![],
            vec![shipping_address],
        );

        let err = et_bundle
            .token
            .clone()
            .load_key(et_kp)
            .unwrap()
            .issue_exemption_token(etr, Expiration::default(), vec![])
            .expect_err("et should not have been issued");

        assert_eq!(
            err,
            IssuanceError::Etr(NonCompliantChildToken {
                causes: vec![NonComplianceCause::ShippingAddress],
            })
        )
    }

    #[test]
    fn cannot_issue_et_with_exemptions_not_present_on_issuing_et() {
        let (et_bundle, et_kp, _) = create_issuing_exemption_token_bundle();

        let exemption = Organism::new(
            "test",
            vec![SequenceIdentifier::Id(GenbankId::try_new("555").unwrap())],
        );
        let etr = ExemptionTokenRequest::v1_token_request(
            None,
            vec![exemption],
            Description::default(),
            vec![],
            vec![],
        );

        let err = et_bundle
            .token
            .clone()
            .load_key(et_kp)
            .unwrap()
            .issue_exemption_token(etr, Expiration::default(), vec![])
            .expect_err("et should not have been issued");

        assert_eq!(
            err,
            IssuanceError::Etr(NonCompliantChildToken {
                causes: vec![NonComplianceCause::Exemptions],
            })
        )
    }

    #[test]
    fn et_dna_sequences() {
        let leaf_cert = create_leaf_cert::<Exemption>();
        let etr = create_etr(vec![Organism::new(
            "Chlamydia psittaci",
            vec![
                SequenceIdentifier::Id(GenbankId::try_new("1112252").unwrap()),
                SequenceIdentifier::Id(GenbankId::try_new("1112253").unwrap()),
                SequenceIdentifier::Dna(
                    Sequence::try_new(
                        ">Virus1\nAC\nT\n>Empty\n\n>Virus2\n>with many\n>comment lines\nC  AT",
                    )
                    .unwrap(),
                ),
            ],
        )]);

        let issuer_auth_devices = Vec::new();

        let et = leaf_cert
            .issue_exemption_token(
                etr,
                Expiration::expiring_in_days(90).unwrap(),
                issuer_auth_devices,
            )
            .unwrap();

        let dnas = et
            .dna_sequences()
            .map(|dna| dna.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            dnas,
            vec!["ACT".to_owned(), "".to_owned(), "CAT".to_owned()]
        )
    }
}
