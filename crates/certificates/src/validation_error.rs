// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::shared_components::common::OutsideValidityPeriod;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

pub const EXPIRED_TEXT: &str = "Expired";
pub const NOT_YET_VALID_TEXT: &str = "Not yet valid";
pub const INVALID_SIGNATURE_TEXT: &str = "The signature failed verification";
pub const REVOKED_TEXT: &str = "Revoked";

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
// tsgen
pub enum InvalidityCause {
    ValidityPeriod(OutsideValidityPeriod),
    SignatureFailure,
    Revoked,
}

impl InvalidityCause {
    pub fn user_friendly_text(&self) -> &str {
        match self {
            Self::ValidityPeriod(reason) => match reason {
                OutsideValidityPeriod::Expired => "expiry",
                OutsideValidityPeriod::NotYetValid => "a validity period that has not yet started",
            },
            Self::SignatureFailure => "signature verification failure",
            Self::Revoked => "revocation",
        }
    }
}

impl Display for InvalidityCause {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidityCause::ValidityPeriod(reason) => match reason {
                OutsideValidityPeriod::Expired => {
                    write!(f, "{}", EXPIRED_TEXT)
                }
                OutsideValidityPeriod::NotYetValid => {
                    write!(f, "{}", NOT_YET_VALID_TEXT)
                }
            },
            InvalidityCause::SignatureFailure => {
                write!(f, "{}", INVALID_SIGNATURE_TEXT)
            }
            InvalidityCause::Revoked => {
                write!(f, "{}", REVOKED_TEXT)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
// tsgen
pub struct ValidationError {
    pub causes: Vec<InvalidityCause>,
}

impl ValidationError {
    pub fn new(causes: Vec<InvalidityCause>) -> Self {
        Self { causes }
    }
    pub fn user_friendly_text(&self) -> String {
        self.causes
            .iter()
            .map(|cause| cause.user_friendly_text())
            .collect::<Vec<_>>()
            .join(" and ")
    }
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.causes.len() == 1 {
            write!(f, "INVALID: {}", self.causes[0])?;
        }
        if self.causes.len() > 1 {
            writeln!(f, "INVALID:")?;
            let mut causes_iter = self.causes.iter().peekable();
            while let Some(cause) = causes_iter.next() {
                if causes_iter.peek().is_some() {
                    writeln!(f, "{}", cause)?;
                } else {
                    write!(f, "{}", cause)?;
                }
            }
        }
        Ok(())
    }
}
