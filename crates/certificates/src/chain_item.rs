// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::tokens::exemption::exemption_list::ExemptionListTokenDigest;
use crate::tokens::infrastructure::database::DatabaseTokenDigest;
use crate::tokens::infrastructure::hlt::HltTokenDigest;
use crate::tokens::infrastructure::keyserver::KeyserverTokenDigest;
use crate::tokens::manufacturer::synthesizer::SynthesizerTokenDigest;
use crate::validation_failure::ValidationFailure;
use crate::{
    Certificate, CertificateDigest, DatabaseToken, Exemption, ExemptionListToken, Formattable,
    HltToken, Infrastructure, Issued, KeyUnavailable, KeyserverToken, Manufacturer, PublicKey,
    Role, SynthesizerToken,
};
use serde::Serialize;
use std::fmt::{Display, Formatter};

/// A certificate or token which is part of a certificate hierarchy, extending from a root certificate to a token.
#[derive(Debug, Serialize, PartialEq, Eq, Hash, Clone)]
pub enum ChainItem<R: Role> {
    Certificate(Certificate<R, KeyUnavailable>),
    ExemptionListToken(ExemptionListToken),
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
impl From<ExemptionListToken> for ChainItem<Exemption> {
    fn from(value: ExemptionListToken) -> Self {
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
    pub(crate) fn validate(&self) -> Result<(), ValidationFailure> {
        match self {
            Self::Certificate(c) => c.validate(),
            Self::ExemptionListToken(t) => t.validate(),
            Self::KeyserverToken(t) => t.validate(),
            Self::HltToken(t) => t.validate(),
            Self::DatabaseToken(t) => t.validate(),
            Self::SynthesizerToken(t) => t.validate(),
        }
    }

    pub(crate) fn was_issued_by_item(&self, item: &ChainItem<R>) -> bool {
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
