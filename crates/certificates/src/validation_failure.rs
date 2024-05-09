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
pub enum InvalidityCause {
    ValidityPeriod(OutsideValidityPeriod),
    SignatureFailure,
    Revoked,
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
pub struct ValidationFailure {
    pub causes: Vec<InvalidityCause>,
}

impl ValidationFailure {
    pub fn new(causes: Vec<InvalidityCause>) -> Self {
        Self { causes }
    }
}

impl Display for ValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.causes.len() == 1 {
            writeln!(f, "INVALID: {}", self.causes[0])?;
        }
        if self.causes.len() > 1 {
            writeln!(f, "INVALID:")?;
            for cause in &self.causes {
                writeln!(f, "{}", cause)?;
            }
        }
        Ok(())
    }
}
