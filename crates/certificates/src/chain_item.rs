// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::revocation::RevocationList;
use crate::tokens::exemption::digest::ExemptionTokenDigest;
use crate::tokens::infrastructure::digest::{
    DatabaseTokenDigest, HltTokenDigest, KeyserverTokenDigest,
};
use crate::tokens::manufacturer::digest::SynthesizerTokenDigest;
use crate::validation_error::{InvalidityCause, ValidationError};
use crate::{
    Certificate, CertificateDigest, DatabaseToken, Digestible, Exemption, ExemptionToken,
    Expiration, HierarchyKind, HltToken, Infrastructure, Issued, KeyUnavailable, KeyserverToken,
    Manufacturer, PublicKey, Role, SynthesizerToken,
};
use rasn::{AsnType, Decode, Encode};
use serde::Serialize;
use std::fmt::{Display, Formatter};

/// A certificate or token which is part of a certificate hierarchy, extending from a root certificate to a token.
#[derive(
    Debug, Serialize, PartialEq, Eq, Hash, Clone, PartialOrd, Ord, Encode, Decode, AsnType,
)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum ChainItem<R>
where
    R: Role,
{
    Certificate(Certificate<R, KeyUnavailable>),
    ExemptionToken(ExemptionToken<KeyUnavailable>),
    KeyserverToken(KeyserverToken<KeyUnavailable>),
    DatabaseToken(DatabaseToken<KeyUnavailable>),
    HltToken(HltToken<KeyUnavailable>),
    SynthesizerToken(SynthesizerToken<KeyUnavailable>),
}

impl<R: Role> From<Certificate<R, KeyUnavailable>> for ChainItem<R> {
    fn from(value: Certificate<R, KeyUnavailable>) -> Self {
        Self::Certificate(value)
    }
}
impl From<ExemptionToken<KeyUnavailable>> for ChainItem<Exemption> {
    fn from(value: ExemptionToken<KeyUnavailable>) -> Self {
        Self::ExemptionToken(value)
    }
}

impl From<KeyserverToken<KeyUnavailable>> for ChainItem<Infrastructure> {
    fn from(value: KeyserverToken<KeyUnavailable>) -> Self {
        Self::KeyserverToken(value)
    }
}

impl From<DatabaseToken<KeyUnavailable>> for ChainItem<Infrastructure> {
    fn from(value: DatabaseToken<KeyUnavailable>) -> Self {
        Self::DatabaseToken(value)
    }
}

impl From<HltToken<KeyUnavailable>> for ChainItem<Infrastructure> {
    fn from(value: HltToken<KeyUnavailable>) -> Self {
        Self::HltToken(value)
    }
}

impl From<SynthesizerToken<KeyUnavailable>> for ChainItem<Manufacturer> {
    fn from(value: SynthesizerToken<KeyUnavailable>) -> Self {
        Self::SynthesizerToken(value)
    }
}

impl<R: Role> ChainItem<R> {
    pub fn validate(&self, list: Option<&RevocationList>) -> Result<(), ValidationError> {
        let revoked = list.is_some_and(|list| self.has_been_revoked(list));
        let signature_expiry_result = self.check_signature_and_expiry();

        if !revoked {
            signature_expiry_result
        } else {
            let mut causes = vec![InvalidityCause::Revoked];

            if let Err(error) = signature_expiry_result {
                causes.extend(error.causes)
            }

            Err(ValidationError::new(causes))
        }
    }

    /// Provides a short description including brief identifying information.
    pub fn user_friendly_text(&self) -> String {
        match self {
            Self::Certificate(c) => format!(
                "{} certificate belonging to '{}'",
                c.hierarchy_level(),
                c.requestor_description()
            ),
            Self::ExemptionToken(t) => {
                format!(
                    "exemption token belonging to '{}'",
                    t.requestor_description()
                )
            }
            Self::KeyserverToken(t) => {
                format!("keyserver token with keyserver id {}", t.keyserver_id())
            }
            Self::DatabaseToken(_) => "database token".to_string(),
            Self::HltToken(_) => "hlt token".to_string(),
            Self::SynthesizerToken(t) => {
                format!(
                    "synthesizer token registered to '{}'",
                    t.manufacturer_domain()
                )
            }
        }
    }

    pub(crate) fn check_signature_and_expiry(&self) -> Result<(), ValidationError> {
        match self {
            Self::Certificate(c) => c.check_signature_and_expiry(),
            Self::ExemptionToken(t) => t.check_signature_and_expiry(),
            Self::KeyserverToken(t) => t.check_signature_and_expiry(),
            Self::HltToken(t) => t.check_signature_and_expiry(),
            Self::DatabaseToken(t) => t.check_signature_and_expiry(),
            Self::SynthesizerToken(t) => t.check_signature_and_expiry(),
        }
    }

    pub(crate) fn valid_issuance_by(&self, item: &ChainItem<R>) -> bool {
        match (self, item) {
            (Self::Certificate(cert_a), Self::Certificate(cert_b)) => {
                cert_a.was_issued_by_cert(cert_b)
            }
            (Self::KeyserverToken(token), Self::Certificate(cert)) => {
                token.was_issued_by_cert(cert)
            }
            (Self::DatabaseToken(token), Self::Certificate(cert)) => token.was_issued_by_cert(cert),
            (Self::ExemptionToken(token), Self::Certificate(cert)) => {
                token.was_issued_by_cert(cert)
            }
            (Self::HltToken(token), Self::Certificate(cert)) => token.was_issued_by_cert(cert),
            (Self::SynthesizerToken(token), Self::Certificate(cert)) => {
                token.was_issued_by_cert(cert)
            }
            (Self::ExemptionToken(child), Self::ExemptionToken(parent)) => {
                parent.try_public_key().is_some_and(|public_key| {
                    child.was_issued_by_public_key(public_key)
                        && parent.check_issuance_constraints(child).is_ok()
                })
            }
            _ => false,
        }
    }

    pub(crate) fn was_issued_by_public_key(&self, public_key: &PublicKey) -> bool {
        match self {
            Self::Certificate(cert_a) => cert_a.was_issued_by_public_key(public_key),
            Self::KeyserverToken(token) => token.was_issued_by_public_key(public_key),
            Self::DatabaseToken(token) => token.was_issued_by_public_key(public_key),
            Self::ExemptionToken(token) => token.was_issued_by_public_key(public_key),
            Self::HltToken(token) => token.was_issued_by_public_key(public_key),
            Self::SynthesizerToken(token) => token.was_issued_by_public_key(public_key),
        }
    }

    pub(crate) fn has_been_revoked(&self, list: &RevocationList) -> bool {
        match self {
            ChainItem::Certificate(c) => list.item_id_or_public_key_has_been_revoked(c),
            ChainItem::ExemptionToken(t) => {
                list.item_id_has_been_revoked(t)
                    || t.try_public_key()
                        .is_some_and(|public_key| list.public_key_has_been_revoked(public_key))
            }
            ChainItem::KeyserverToken(t) => list.item_id_or_public_key_has_been_revoked(t),
            ChainItem::DatabaseToken(t) => list.item_id_or_public_key_has_been_revoked(t),
            ChainItem::HltToken(t) => list.item_id_or_public_key_has_been_revoked(t),
            ChainItem::SynthesizerToken(t) => list.item_id_or_public_key_has_been_revoked(t),
        }
    }

    pub(crate) fn is_at_hierarchy_level(&self, level: &HierarchyKind) -> bool {
        matches!(self, ChainItem::Certificate(c) if c.hierarchy_level() == *level)
    }

    pub(crate) fn is_at_or_below_hierarchy_level(&self, level: &HierarchyKind) -> bool {
        match self {
            ChainItem::Certificate(c) => c.hierarchy_level() <= *level,
            _ => true,
        }
    }

    pub(crate) fn expiration(&self) -> &Expiration {
        match self {
            ChainItem::Certificate(c) => c.expiration(),
            ChainItem::ExemptionToken(t) => t.expiration(),
            ChainItem::KeyserverToken(t) => t.expiration(),
            ChainItem::DatabaseToken(t) => t.expiration(),
            ChainItem::HltToken(t) => t.expiration(),
            ChainItem::SynthesizerToken(t) => t.expiration(),
        }
    }
}

#[derive(Serialize)]
// tsgen = {Certificate: CertificateDigest} | {ExemptionToken: ExemptionTokenDigest}
pub enum ChainItemDigest {
    Certificate(CertificateDigest),
    ExemptionToken(ExemptionTokenDigest),
    KeyserverToken(KeyserverTokenDigest),
    DatabaseToken(DatabaseTokenDigest),
    HltToken(HltTokenDigest),
    SynthesizerToken(SynthesizerTokenDigest),
}

impl<R: Role> Digestible for ChainItem<R> {
    type Digest = ChainItemDigest;
}

impl Display for ChainItemDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainItemDigest::Certificate(c) => {
                write!(f, "{}", c)
            }
            ChainItemDigest::ExemptionToken(t) => {
                write!(f, "{}", t)
            }
            ChainItemDigest::KeyserverToken(t) => {
                write!(f, "{}", t)
            }
            ChainItemDigest::DatabaseToken(t) => {
                write!(f, "{}", t)
            }
            ChainItemDigest::HltToken(t) => {
                write!(f, "{}", t)
            }
            ChainItemDigest::SynthesizerToken(t) => {
                write!(f, "{}", t)
            }
        }
    }
}

impl<R: Role> From<ChainItem<R>> for ChainItemDigest {
    fn from(value: ChainItem<R>) -> Self {
        match value {
            ChainItem::Certificate(c) => Self::Certificate(c.into()),
            ChainItem::ExemptionToken(t) => Self::ExemptionToken(t.into()),
            ChainItem::KeyserverToken(t) => Self::KeyserverToken(t.into()),
            ChainItem::DatabaseToken(t) => Self::DatabaseToken(t.into()),
            ChainItem::HltToken(t) => Self::HltToken(t.into()),
            ChainItem::SynthesizerToken(t) => Self::SynthesizerToken(t.into()),
        }
    }
}

/// Holds both the item that failed validation and the error that occurred.
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct ChainItemValidationError<R: Role> {
    pub item: ChainItem<R>,
    pub error: ValidationError,
}

impl<R: Role> ChainItemValidationError<R> {
    pub fn new(item: ChainItem<R>, error: ValidationError) -> Self {
        Self { item, error }
    }
}

impl<R: Role> Display for ChainItemValidationError<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.item.clone().into_digest())?;
        write!(f, "{}", self.error)
    }
}

#[derive(Serialize)]
// tsgen
pub struct ChainItemDigestValidationError {
    digest: ChainItemDigest,
    error: ValidationError,
}

impl ChainItemDigestValidationError {
    pub fn new<R: Role>(item: impl Into<ChainItem<R>>, error: ValidationError) -> Self {
        let chain_item = item.into();
        Self {
            digest: chain_item.into_digest(),
            error,
        }
    }
}

impl<R: Role> From<ChainItemValidationError<R>> for ChainItemDigestValidationError {
    fn from(value: ChainItemValidationError<R>) -> Self {
        ChainItemDigestValidationError::new(value.item, value.error)
    }
}

#[cfg(test)]
mod test {
    use doprf::party::KeyserverId;

    use crate::{
        chain_item::ChainItemValidationError,
        test_helpers::{
            create_leaf_cert, expected_cert_display, expected_database_token_display,
            expected_hlt_token_display, expected_keyserver_token_display,
            expected_synthesizer_token_display, BreakableSignature,
        },
        Builder, ChainItem, DatabaseTokenRequest, Expiration, HltTokenRequest, Infrastructure,
        Issued, IssuerAdditionalFields, KeyPair, KeyserverTokenRequest, Manufacturer,
        RequestBuilder, SynthesizerTokenRequest,
    };

    #[test]
    fn display_for_root_manufacturer_certificate_with_invalid_signature_matches_expected_display() {
        let kp = KeyPair::new_random();
        let mut cert = RequestBuilder::<Manufacturer>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        cert.break_signature();
        let public_key = cert.public_key();

        let mut expected_text = expected_cert_display(
            &cert,
            "Root",
            "Manufacturer",
            &format!("(public key: {public_key})"),
            &format!("(public key: {public_key})"),
            None,
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        let item: ChainItem<Manufacturer> = cert.into();
        let error = item
            .validate(None)
            .map_err(|err| ChainItemValidationError::new(item, err))
            .expect_err("Expected validation to fail");
        assert_eq!(error.to_string(), expected_text);
    }

    #[test]
    fn display_for_database_token_failure_warns_if_signature_invalid() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = DatabaseTokenRequest::v1_token_request(kp.public_key());

        let mut token = cert
            .issue_database_token(req, Expiration::default())
            .unwrap();
        token.break_signature();

        let mut expected_text = expected_database_token_display(
            &token,
            &format!("(public key: {})", token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        let item: ChainItem<Infrastructure> = token.into();
        let error = item
            .validate(None)
            .map_err(|err| ChainItemValidationError::new(item, err))
            .expect_err("Expected validation to fail");
        assert_eq!(error.to_string(), expected_text);
    }

    #[test]
    fn display_for_keyserver_token_failure_warns_if_signature_invalid() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = KeyserverTokenRequest::v1_token_request(
            kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let mut token = cert
            .issue_keyserver_token(req, Expiration::default())
            .unwrap();
        token.break_signature();

        let mut expected_text = expected_keyserver_token_display(
            &token,
            "1",
            &format!("(public key: {})", token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        let item: ChainItem<Infrastructure> = token.into();
        let error = item
            .validate(None)
            .map_err(|err| ChainItemValidationError::new(item, err))
            .expect_err("Expected validation to fail");
        assert_eq!(error.to_string(), expected_text);
    }

    #[test]
    fn display_for_hlt_token_warns_if_signature_invalid() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = HltTokenRequest::v1_token_request(kp.public_key());

        let mut token = cert.issue_hlt_token(req, Expiration::default()).unwrap();
        token.break_signature();

        let mut expected_text = expected_hlt_token_display(
            &token,
            &format!("(public key: {})", token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        let item: ChainItem<Infrastructure> = token.into();
        let error = item
            .validate(None)
            .map_err(|err| ChainItemValidationError::new(item, err))
            .expect_err("Expected validation to fail");
        assert_eq!(error.to_string(), expected_text);
    }

    #[test]
    fn display_for_synthesizer_token_failure_warns_if_signature_invalid() {
        let cert = create_leaf_cert::<Manufacturer>();
        let kp = KeyPair::new_random();
        let req = SynthesizerTokenRequest::v1_token_request(
            kp.public_key(),
            "maker.synth",
            "XL",
            "10AK",
            10_000u64,
            None,
        );
        let mut token = cert
            .issue_synthesizer_token(req, Expiration::default())
            .unwrap();

        token.break_signature();

        let mut expected_text = expected_synthesizer_token_display(
            &token,
            "maker.synth",
            "XL",
            "10AK",
            "10000 base pairs per day",
            None,
            &format!("(public key: {})", token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        let item: ChainItem<Manufacturer> = token.into();
        let error = item
            .validate(None)
            .map_err(|err| ChainItemValidationError::new(item, err))
            .expect_err("Expected validation to fail");
        assert_eq!(error.to_string(), expected_text);
    }
}
