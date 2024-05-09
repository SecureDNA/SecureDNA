// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module contains functionality for creating an `ExemptionListTokenRequest`.
//! A `Certificate` is able to sign a `ExemptionListTokenRequest` to issue a `ExemptionListToken`.

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
    Formattable, IssuanceError, KeyAvailable, KeyMismatchError, KeyPair, KeyUnavailable,
};

use super::{authenticator::Authenticator, organism::Organism};

// tsgen
type ShippingAddress = Vec<String>;

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
pub(crate) struct ExemptionListTokenRequest1 {
    guard: ComponentVersionGuard<Self>,
    /// unique for each token
    request_id: Id,
    public_key: Option<PublicKey>,
    exemptions: Vec<Organism>,
    requestor: Description,
    requestor_auth_devices: Vec<Authenticator>,
    shipping_addresses: Vec<ShippingAddress>,
}

impl ExemptionListTokenRequest1 {
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
impl VersionedComponent for ExemptionListTokenRequest1 {
    const COMPONENT_NAME: &'static str = "ELTR";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all ELTR versions.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// tsgen
#[rasn(automatic_tags)]
#[rasn(choice)]
pub(crate) enum ExemptionListTokenRequestVersion {
    V1(ExemptionListTokenRequest1),
}

impl ExemptionListTokenRequestVersion {
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

    pub(crate) fn try_public_key(&self) -> Option<&PublicKey> {
        match self {
            Self::V1(r) => r.public_key.as_ref(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
// tsgen
pub struct ExemptionListTokenRequest {
    pub(crate) version: ExemptionListTokenRequestVersion,
}

impl ExemptionListTokenRequest {
    pub(crate) fn new(version: ExemptionListTokenRequestVersion) -> Self {
        Self { version }
    }

    pub fn v1_token_request(
        public_key: Option<PublicKey>,
        exemptions: Vec<Organism>,
        requestor: Description,
        requestor_auth_devices: Vec<Authenticator>,
        shipping_addresses: Vec<ShippingAddress>,
    ) -> Self {
        let request = ExemptionListTokenRequest1::new(
            public_key,
            exemptions,
            requestor,
            requestor_auth_devices,
            shipping_addresses,
        );
        let version = ExemptionListTokenRequestVersion::V1(request);
        ExemptionListTokenRequest::new(version)
    }

    pub fn exemptions(&self) -> &[Organism] {
        self.version.exemptions()
    }

    pub fn shipping_addresses(&self) -> &[ShippingAddress] {
        self.version.shipping_addresses()
    }

    pub fn try_public_key(&self) -> Option<&PublicKey> {
        self.version.try_public_key()
    }
}

impl PemTaggable for ExemptionListTokenRequest {
    fn tag() -> String {
        "SECUREDNA EXEMPTION LIST TOKEN REQUEST".to_string()
    }
}

impl Decode for ExemptionListTokenRequest {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version = ExemptionListTokenRequestVersion::decode_with_tag_and_constraints(
            decoder,
            tag,
            constraints,
        )?;
        Ok(ExemptionListTokenRequest::new(version))
    }
}

/// Data that will be signed by the issuer of the ELT
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
pub(crate) struct ExemptionListTokenIssuer1 {
    guard: ComponentVersionGuard<Self>,
    issuance_id: Id,
    identity: CompatibleIdentity,
    expiration: Expiration,
    issuer_auth_devices: Vec<Authenticator>,
    emails_to_notify: Vec<String>,
}

impl ExemptionListTokenIssuer1 {
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

impl VersionedComponent for ExemptionListTokenIssuer1 {
    const COMPONENT_NAME: &'static str = "ELTI";
    const ITERATION: u16 = 1;
}

/// Enum wrapping all ELT versions.
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
pub(crate) enum ExemptionListTokenVersion {
    V1(Signed<TokenData<ExemptionListTokenRequest1, ExemptionListTokenIssuer1>>),
}

impl ExemptionListTokenVersion {
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

    pub(crate) fn issue_elt(
        &self,
        request: ExemptionListTokenRequest,
        expiration: Expiration,
        issuer_auth_devices: Vec<Authenticator>,
        kp: &KeyPair,
    ) -> Result<Self, IssuanceError> {
        match (self, request.version) {
            (Self::V1(t), ExemptionListTokenRequestVersion::V1(request)) => {
                let issuer = CompatibleIdentity {
                    pk: kp.public_key(),
                    desc: t.data.request.requestor.to_string(),
                };

                let mut emails_to_notify = self.emails_to_notify().to_owned();
                if let Some(email) = &t.data.request.requestor.email {
                    emails_to_notify.push(email.clone());
                }

                let signed_data = issue_elt_v1_with_keypair(
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

    pub(crate) fn request(&self) -> ExemptionListTokenRequestVersion {
        match self {
            ExemptionListTokenVersion::V1(t) => {
                ExemptionListTokenRequestVersion::V1(t.data.request.clone())
            }
        }
    }
}

fn issue_elt_v1_with_keypair(
    request: ExemptionListTokenRequest1,
    issuer: CompatibleIdentity,
    emails_to_notify: Vec<String>,
    expiration: Expiration,
    issuer_auth_devices: Vec<Authenticator>,
    keypair: &KeyPair,
) -> Result<Signed<TokenData<ExemptionListTokenRequest1, ExemptionListTokenIssuer1>>, EncodeError> {
    let issuer_fields =
        ExemptionListTokenIssuer1::new(issuer, expiration, issuer_auth_devices, emails_to_notify);

    let elt = TokenData {
        request,
        issuer_fields,
    };
    keypair.sign_asn_encodable_data(elt)
}

/// Token to allow the synthesis of restricted hazards
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
// tsgen
pub struct ExemptionListToken<K> {
    pub(crate) version: ExemptionListTokenVersion,
    key_state: K,
}

impl<K> ExemptionListToken<K> {
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

    pub fn request(&self) -> ExemptionListTokenRequest {
        ExemptionListTokenRequest::new(self.version.request())
    }

    /// Whether the child ELT's issuance complies with all requirements
    pub fn check_issuance_constraints(
        &self,
        child_elt: &ExemptionListToken<KeyUnavailable>,
    ) -> Result<(), IssuanceError> {
        self.check_ability_to_issue(&child_elt.request())?;

        // All parent ELT emails to notify should appear in child ELT
        if self
            .emails_to_notify()
            .iter()
            .all(|email| child_elt.emails_to_notify().contains(email))
        {
            return Ok(());
        }
        Err(NonCompliantEltr::Email.into())
    }

    /// Whether this ELTR fulfills the necessary requirements in order to be issued by the ELT
    fn check_ability_to_issue(
        &self,
        eltr: &ExemptionListTokenRequest,
    ) -> Result<(), NonCompliantEltr> {
        // We can't allow a child ELT to contain exemptions
        // that are not on the parent
        for organism in eltr.exemptions() {
            if !self.exemptions().contains(organism) {
                return Err(NonCompliantEltr::Exemptions);
            }
        }
        // We can't allow a child ELT to contain shipping addresses
        // that are not on the parent
        for address in eltr.shipping_addresses() {
            if !self.shipping_addresses().contains(address) {
                return Err(NonCompliantEltr::ShippingAddress);
            }
        }
        // We don't want to allow child ELTs which can issue further ELTs
        if eltr.try_public_key().is_some() {
            return Err(NonCompliantEltr::AssociatedKeyNotAllowed);
        }
        Ok(())
    }
}

impl ExemptionListToken<KeyUnavailable> {
    pub(crate) fn new(version: ExemptionListTokenVersion) -> Self {
        Self {
            version,
            key_state: KeyUnavailable,
        }
    }
    pub fn load_key(
        self,
        keypair: KeyPair,
    ) -> Result<ExemptionListToken<KeyAvailable>, EltLoadKeyError> {
        match self.try_public_key() {
            None => Err(EltLoadKeyError::NoAssociatedKey),
            Some(public_key) => {
                let key_state = KeyUnavailable::load_key(keypair, public_key)?;
                Ok(ExemptionListToken {
                    version: self.version,
                    key_state,
                })
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum EltLoadKeyError {
    #[error(transparent)]
    Mismatch(#[from] KeyMismatchError),
    #[error("The exemption list token does not have an associated keypair")]
    NoAssociatedKey,
}

#[derive(Error, Debug, PartialEq)]
pub enum NonCompliantEltr {
    #[error(
        "The child token does not contain all the 'emails to notify' found on the issuing token"
    )]
    Email,
    #[error("The exemptions on the child token are no a subset of those on the issuer")]
    Exemptions,
    #[error("The shipping addresses on the child token are not a subset of those on the issuer")]
    ShippingAddress,
    #[error("A child exemption list token cannot have an associated keypair")]
    AssociatedKeyNotAllowed,
}

impl ExemptionListToken<KeyAvailable> {
    pub fn issue_elt(
        &self,
        eltr: ExemptionListTokenRequest,
        expiration: Expiration,
        auth_devices: Vec<Authenticator>,
    ) -> Result<ExemptionListToken<KeyUnavailable>, IssuanceError> {
        self.check_ability_to_issue(&eltr)?;
        let elt_version =
            self.version
                .issue_elt(eltr, expiration, auth_devices, self.key_state.kp())?;
        Ok(ExemptionListToken::new(elt_version))
    }
}

impl<K> PemTaggable for ExemptionListToken<K> {
    fn tag() -> String {
        "SECUREDNA EXEMPTION LIST TOKEN".to_string()
    }
}

impl Decode for ExemptionListToken<KeyUnavailable> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let version =
            ExemptionListTokenVersion::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(ExemptionListToken::new(version))
    }
}

/// Related types for ExemptionListToken
#[derive(AsnType, Clone, Encode, Decode, Debug)]
pub struct ExemptionListTokenGroup;

impl TokenGroup for ExemptionListTokenGroup {
    type AssociatedRole = Exemption;
    type TokenRequest = ExemptionListTokenRequest;
    type Token = ExemptionListToken<KeyUnavailable>;
    type ChainType = Chain<Self::AssociatedRole>;
}

impl_boilerplate_for_token_request_version! {ExemptionListTokenRequestVersion, V1}
impl_boilerplate_for_token_request! {ExemptionListTokenRequest}
impl_encoding_boilerplate! {ExemptionListTokenRequest}

impl_boilerplate_for_token_version! {ExemptionListTokenVersion, V1}
impl_boilerplate_for_token! {ExemptionListToken<K>}
impl_encoding_boilerplate! {ExemptionListToken<K>}

#[derive(Serialize)]
pub struct ExemptionListTokenRequestDigest {
    request_id: Id,
    public_key: Option<PublicKey>,
    exemptions: Vec<Organism>,
    requestor: Description,
    requestor_auth_devices: Vec<Authenticator>,
    shipping_addresses: Vec<ShippingAddress>,
}

impl Formattable for ExemptionListTokenRequest {
    type Digest = ExemptionListTokenRequestDigest;
}

impl From<ExemptionListTokenRequest> for ExemptionListTokenRequestDigest {
    fn from(value: ExemptionListTokenRequest) -> Self {
        match value.version {
            ExemptionListTokenRequestVersion::V1(r) => {
                let request_id = r.request_id;
                let exemptions = r.exemptions;
                let requestor = r.requestor;
                let requestor_auth_devices = r.requestor_auth_devices;
                let shipping_addresses = r.shipping_addresses;
                let public_key = r.public_key;
                ExemptionListTokenRequestDigest {
                    request_id,
                    public_key,
                    exemptions,
                    requestor,
                    requestor_auth_devices,
                    shipping_addresses,
                }
            }
        }
    }
}

impl Display for ExemptionListTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Plaintext display for this token has not yet been implemented"
        )
    }
}

#[derive(Serialize)]
pub struct ExemptionListTokenDigest {
    request_id: Id,
    public_key: Option<PublicKey>,
    requestor: Description,
    requestor_auth_devices: Vec<Authenticator>,
    shipping_addresses: Vec<ShippingAddress>,
    issuance_id: Id,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    issuer_auth_devices: Vec<Authenticator>,
    emails_to_notify: Vec<String>,
    signature: Signature,
    signature_verifies: bool,
}

impl<K> Formattable for ExemptionListToken<K> {
    type Digest = ExemptionListTokenDigest;
}

impl<K> From<ExemptionListToken<K>> for ExemptionListTokenDigest {
    fn from(value: ExemptionListToken<K>) -> Self {
        let signature_verifies = value.signature_verifies();
        match value.version {
            ExemptionListTokenVersion::V1(t) => {
                let request_id = t.data.request.request_id;
                let requestor = t.data.request.requestor;
                let requestor_auth_devices = t.data.request.requestor_auth_devices;
                let shipping_addresses = t.data.request.shipping_addresses;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let issued_by = t.data.issuer_fields.identity;
                let expiration = t.data.issuer_fields.expiration;
                let issuer_auth_devices = t.data.issuer_fields.issuer_auth_devices;
                let emails_to_notify = t.data.issuer_fields.emails_to_notify;
                let signature = t.signature;
                let public_key = t.data.request.public_key;

                ExemptionListTokenDigest {
                    request_id,
                    public_key,
                    requestor,
                    requestor_auth_devices,
                    shipping_addresses,
                    issuance_id,
                    issued_by,
                    expiration,
                    issuer_auth_devices,
                    emails_to_notify,
                    signature,
                    signature_verifies,
                }
            }
        }
    }
}

impl Display for ExemptionListTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Plaintext display for this token has not yet been implemented"
        )
    }
}

#[cfg(test)]
pub fn issue_elt_without_compliance_check(
    eltr: ExemptionListTokenRequest,
    kp: &KeyPair,
    emails_to_notify: Vec<String>,
) -> ExemptionListToken<KeyUnavailable> {
    match eltr.version {
        ExemptionListTokenRequestVersion::V1(v1) => {
            let issuer_identity = CompatibleIdentity {
                pk: kp.public_key(),
                desc: String::new(),
            };
            let inner = issue_elt_v1_with_keypair(
                v1,
                issuer_identity,
                emails_to_notify,
                Expiration::default(),
                vec![],
                kp,
            )
            .unwrap();
            ExemptionListToken::new(ExemptionListTokenVersion::V1(inner))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::{
        create_eltr_with_options, create_issuing_exemption_list_token_bundle,
    };
    use crate::tokens::exemption::exemption_list::NonCompliantEltr;
    use crate::{
        test_helpers::{create_eltr, create_exemptions, create_leaf_cert},
        Description, Exemption, ExemptionListToken, ExemptionListTokenRequest, Expiration,
        GenbankId, IssuanceError, KeyPair, Organism, PemDecodable, PemEncodable, Sequence,
        SequenceIdentifier,
    };

    #[test]
    fn can_issue_exemption_token() {
        let cert = create_leaf_cert::<Exemption>();
        let request = create_eltr(create_exemptions());
        cert.issue_elt(request, Expiration::default(), vec![])
            .unwrap();
    }

    #[test]
    fn can_serialise_eltr_to_pem() {
        let eltr = create_eltr(create_exemptions());
        let encoded = eltr.to_pem().unwrap();
        let eltr_decoded = ExemptionListTokenRequest::from_pem(encoded).unwrap();
        assert_eq!(eltr, eltr_decoded);
    }

    #[test]
    fn can_serialise_elt_to_pem() {
        let leaf_cert = create_leaf_cert::<Exemption>();
        let eltr = create_eltr(create_exemptions());

        let issuer_auth_devices = Vec::new();

        let elt = leaf_cert
            .issue_elt(
                eltr,
                Expiration::expiring_in_days(90).unwrap(),
                issuer_auth_devices,
            )
            .unwrap();

        let encoded = elt.to_pem().unwrap();
        let elt_decoded = ExemptionListToken::from_pem(encoded).unwrap();

        assert_eq!(elt, elt_decoded);
    }

    #[test]
    fn can_issue_elt_from_elt() {
        let (elt_bundle, elt_kp, _) = create_issuing_exemption_list_token_bundle();

        let child_eltr = create_eltr_with_options(None, vec![], vec![]);
        elt_bundle
            .token
            .clone()
            .load_key(elt_kp)
            .unwrap()
            .issue_elt(child_eltr, Expiration::default(), vec![])
            .expect("elt should have been able to issue a further elt");
    }

    #[test]
    fn cannot_issue_child_elt_with_associated_key() {
        let (elt_bundle, elt_kp, _) = create_issuing_exemption_list_token_bundle();

        let child_kp = KeyPair::new_random();
        let child_eltr = create_eltr_with_options(Some(child_kp.public_key()), vec![], vec![]);

        let err = elt_bundle
            .token
            .clone()
            .load_key(elt_kp)
            .unwrap()
            .issue_elt(child_eltr, Expiration::default(), vec![])
            .expect_err("elt should not have been issued");

        assert_eq!(
            err,
            IssuanceError::Eltr(NonCompliantEltr::AssociatedKeyNotAllowed)
        )
    }

    #[test]
    fn cannot_issue_elt_with_shipping_address_not_present_on_issuing_elt() {
        let (elt_bundle, elt_kp, _) = create_issuing_exemption_list_token_bundle();

        let shipping_address = vec!["22 New Street".to_string(), "Some Other City".to_string()];
        let eltr = ExemptionListTokenRequest::v1_token_request(
            None,
            vec![],
            Description::default(),
            vec![],
            vec![shipping_address],
        );

        let err = elt_bundle
            .token
            .clone()
            .load_key(elt_kp)
            .unwrap()
            .issue_elt(eltr, Expiration::default(), vec![])
            .expect_err("elt should not have been issued");

        assert_eq!(err, IssuanceError::Eltr(NonCompliantEltr::ShippingAddress))
    }

    #[test]
    fn cannot_issue_elt_with_exemptions_not_present_on_issuing_elt() {
        let (elt_bundle, elt_kp, _) = create_issuing_exemption_list_token_bundle();

        let exemption = Organism::new(
            "test",
            vec![SequenceIdentifier::Id(GenbankId::try_new("555").unwrap())],
        );
        let eltr = ExemptionListTokenRequest::v1_token_request(
            None,
            vec![exemption],
            Description::default(),
            vec![],
            vec![],
        );

        let err = elt_bundle
            .token
            .clone()
            .load_key(elt_kp)
            .unwrap()
            .issue_elt(eltr, Expiration::default(), vec![])
            .expect_err("elt should not have been issued");

        assert_eq!(err, IssuanceError::Eltr(NonCompliantEltr::Exemptions))
    }

    #[test]
    fn elt_dna_sequences() {
        let leaf_cert = create_leaf_cert::<Exemption>();
        let eltr = create_eltr(vec![Organism::new(
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

        let elt = leaf_cert
            .issue_elt(
                eltr,
                Expiration::expiring_in_days(90).unwrap(),
                issuer_auth_devices,
            )
            .unwrap();

        let dnas = elt
            .dna_sequences()
            .map(|dna| dna.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            dnas,
            vec!["ACT".to_owned(), "".to_owned(), "CAT".to_owned()]
        )
    }
}
