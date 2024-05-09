// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::revocation::RevocationList;
use crate::tokens::exemption::exemption_list::ExemptionListTokenDigest;
use crate::tokens::infrastructure::database::DatabaseTokenDigest;
use crate::tokens::infrastructure::hlt::HltTokenDigest;
use crate::tokens::infrastructure::keyserver::KeyserverTokenDigest;
use crate::tokens::manufacturer::synthesizer::SynthesizerTokenDigest;
use crate::validation_failure::{InvalidityCause, ValidationFailure};
use crate::{
    Certificate, CertificateDigest, DatabaseToken, Exemption, ExemptionListToken, Formattable,
    HltToken, Infrastructure, Issued, KeyUnavailable, KeyserverToken, Manufacturer, PublicKey,
    Role, SynthesizerToken,
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
    ExemptionListToken(ExemptionListToken<KeyUnavailable>),
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
impl From<ExemptionListToken<KeyUnavailable>> for ChainItem<Exemption> {
    fn from(value: ExemptionListToken<KeyUnavailable>) -> Self {
        Self::ExemptionListToken(value)
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
    pub(crate) fn validate(&self, list: Option<&RevocationList>) -> Result<(), ValidationFailure> {
        let revoked = list.is_some_and(|list| self.has_been_revoked(list));
        let signature_expiry_result = self.check_signature_and_expiry();

        if !revoked {
            signature_expiry_result
        } else {
            let mut validation_failures = vec![InvalidityCause::Revoked];

            if let Err(failure) = signature_expiry_result {
                validation_failures.extend(failure.causes)
            }

            Err(ValidationFailure::new(validation_failures))
        }
    }

    pub(crate) fn check_signature_and_expiry(&self) -> Result<(), ValidationFailure> {
        match self {
            Self::Certificate(c) => c.check_signature_and_expiry(),
            Self::ExemptionListToken(t) => t.check_signature_and_expiry(),
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
            (Self::ExemptionListToken(token), Self::Certificate(cert)) => {
                token.was_issued_by_cert(cert)
            }
            (Self::HltToken(token), Self::Certificate(cert)) => token.was_issued_by_cert(cert),
            (Self::SynthesizerToken(token), Self::Certificate(cert)) => {
                token.was_issued_by_cert(cert)
            }
            (Self::ExemptionListToken(child), Self::ExemptionListToken(parent)) => {
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
            Self::ExemptionListToken(token) => token.was_issued_by_public_key(public_key),
            Self::HltToken(token) => token.was_issued_by_public_key(public_key),
            Self::SynthesizerToken(token) => token.was_issued_by_public_key(public_key),
        }
    }

    pub fn has_been_revoked(&self, list: &RevocationList) -> bool {
        match self {
            ChainItem::Certificate(c) => list.item_id_or_public_key_has_been_revoked(c),
            ChainItem::ExemptionListToken(t) => {
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
}

#[derive(Serialize)]
pub enum ChainItemDigest {
    Certificate(CertificateDigest),
    ExemptionListToken(ExemptionListTokenDigest),
    KeyserverToken(KeyserverTokenDigest),
    DatabaseToken(DatabaseTokenDigest),
    HltToken(HltTokenDigest),
    SynthesizerToken(SynthesizerTokenDigest),
}

impl<R: Role> Formattable for ChainItem<R> {
    type Digest = ChainItemDigest;
}

impl Display for ChainItemDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainItemDigest::Certificate(c) => {
                write!(f, "{}", c)
            }
            ChainItemDigest::ExemptionListToken(t) => {
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
            ChainItem::ExemptionListToken(t) => Self::ExemptionListToken(t.into()),
            ChainItem::KeyserverToken(t) => Self::KeyserverToken(t.into()),
            ChainItem::DatabaseToken(t) => Self::DatabaseToken(t.into()),
            ChainItem::HltToken(t) => Self::HltToken(t.into()),
            ChainItem::SynthesizerToken(t) => Self::SynthesizerToken(t.into()),
        }
    }
}
