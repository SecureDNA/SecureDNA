// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fmt::Display, str::FromStr};

use serde::Serialize;
use thiserror::Error;

/// Trait for types that can be formatted for display in plaintext or json.
/// This could be in digest form or a full representation.
pub trait Formattable: Serialize + Sized {
    type Digest: Serialize + Display + From<Self>;

    fn into_digest(self) -> Self::Digest {
        self.into()
    }

    fn format(self, method: &FormatMethod) -> Result<String, FormatError> {
        match method {
            FormatMethod::PlainDigest => {
                let s = self.into_digest().to_string();
                Ok(s)
            }
            FormatMethod::JsonDigest => {
                let digest = self.into_digest();
                let json = serde_json::to_string_pretty(&digest).map_err(|_| FormatError)?;
                Ok(json)
            }
            FormatMethod::JsonFull => {
                let s = serde_json::to_string(&self).map_err(|_| FormatError)?;
                Ok(s)
            }
        }
    }
}

pub fn format_multiple_items<T: Formattable>(
    items: impl IntoIterator<Item = T>,
    method: &FormatMethod,
) -> Result<String, FormatError> {
    let formatted_items: Result<Vec<_>, _> =
        items.into_iter().map(|item| item.format(method)).collect();
    formatted_items.map(|item| item.join("\n"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatMethod {
    /// Display as a plaintext digest
    PlainDigest,
    /// Display as a json digest
    JsonDigest,
    /// Display as a json serialisation of all fields
    JsonFull,
}

#[derive(Error, Debug, PartialEq)]
#[error("unable to format certificate")]
pub struct FormatError;

#[derive(Error, Debug)]
#[error("could not parse display type, expected one of (plain-digest, json-digest, json-full)")]
pub struct FormatMethodParseError;
impl FromStr for FormatMethod {
    type Err = FormatMethodParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain-digest" => Ok(FormatMethod::PlainDigest),
            "json-digest" => Ok(FormatMethod::JsonDigest),
            "json-full" => Ok(FormatMethod::JsonFull),
            _ => Err(FormatMethodParseError),
        }
    }
}
