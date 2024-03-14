// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::shared_components::common::OutsideValidityPeriod;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

pub const EXPIRED_TEXT: &str = "Expired";
pub const NOT_YET_VALID_TEXT: &str = "Not yet valid";
pub const INVALID_SIGNATURE_TEXT: &str = "The signature failed verification";

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum InvalidityReason {
    ValidityPeriod(OutsideValidityPeriod),
    SignatureFailure,
}

impl Display for InvalidityReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidityReason::ValidityPeriod(reason) => match reason {
                OutsideValidityPeriod::Expired => {
                    write!(f, "{}", EXPIRED_TEXT)
                }
                OutsideValidityPeriod::NotYetValid => {
                    write!(f, "{}", NOT_YET_VALID_TEXT)
                }
            },
            InvalidityReason::SignatureFailure => {
                write!(f, "{}", INVALID_SIGNATURE_TEXT)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct ValidationFailure(Vec<InvalidityReason>);

impl ValidationFailure {
    pub fn new(validation_failures: Vec<InvalidityReason>) -> Self {
        Self(validation_failures)
    }
}

impl Display for ValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.len() == 1 {
            writeln!(f, "INVALID: {}", self.0[0])?;
        }
        if self.0.len() > 1 {
            writeln!(f, "INVALID:")?;
            for reason in &self.0 {
                writeln!(f, "{}", reason)?;
            }
        }
        Ok(())
    }
}
