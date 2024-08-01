// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Display;
use std::str::FromStr;

use clap::Subcommand;
use serde::Serialize;
use thiserror::Error;

use certificates::{
    ChainItem, ChainItemDigest, ChainTraversal, Digestible, PublicKey, Role, ValidationError,
};

use crate::shims::error::CertCliError;

const NO_CHAIN_TEXT: &str = "This item has no certificate chain attached";

pub const NO_PATH_FOUND_TEXT: &str =
    "No valid path found to an issuing certificate with a matching public key";

pub const NO_EXCLUDED_CERTS_TEXT: &str = "No certificates found that were not part of a valid path";

/// View of the certificates in the chain
#[derive(Debug, Subcommand)]
pub enum ChainViewMode {
    /// View all certificates in the supplied chain, regardless of whether they are valid.
    AllCerts,
    /// View all valid paths through the chain certificates to an issuer with a matching public key.
    AllPaths {
        #[clap(
            help = "Public key(s) of issuing certificate(s) that we are attempting to find a path to"
        )]
        public_keys: Vec<PublicKey>,
    },
    /// Any certificates in the supplied chain that do not form part of a valid path.
    NotPartOfPath {
        #[clap(help = "Public key(s) of issuing certificate(s)")]
        public_keys: Vec<PublicKey>,
    },
}

impl ChainViewMode {
    pub fn display_chain(
        &self,
        bundle: impl ChainTraversal,
        method: &FormatMethod,
    ) -> Result<String, CertCliError> {
        match self {
            ChainViewMode::AllCerts => display_all_items_in_chain(bundle, method),
            ChainViewMode::AllPaths { public_keys } => {
                if public_keys.is_empty() {
                    return Err(CertCliError::IssuerPublicKeyRequired);
                }
                display_all_valid_paths(bundle, method, public_keys)
            }
            ChainViewMode::NotPartOfPath { public_keys } => {
                if public_keys.is_empty() {
                    return Err(CertCliError::IssuerPublicKeyRequired);
                }
                display_certs_not_part_of_valid_path(bundle, method, public_keys)
            }
        }
    }
}

pub fn display_all_items_in_chain<B: ChainTraversal>(
    bundle: B,
    format_method: &FormatMethod,
) -> Result<String, CertCliError> {
    let chain = bundle.chain();
    if chain.is_empty() {
        Ok(NO_CHAIN_TEXT.to_string())
    } else {
        let display_text = MultiItemOutput::from_items(chain).format(format_method)?;
        Ok(display_text)
    }
}

pub fn display_all_valid_paths<B: ChainTraversal>(
    bundle: B,
    format_method: &FormatMethod,
    public_keys: &[PublicKey],
) -> Result<String, CertCliError> {
    let all_paths = bundle.find_all_paths_to_issuers(public_keys, None);
    if all_paths.is_empty() {
        return Ok(NO_PATH_FOUND_TEXT.to_string());
    }
    let display_text = display_paths(all_paths, format_method)?;
    Ok(display_text)
}

fn display_certs_not_part_of_valid_path<B: ChainTraversal>(
    bundle: B,
    format_method: &FormatMethod,
    public_keys: &[PublicKey],
) -> Result<String, CertCliError> {
    let excluded_certs = bundle.find_items_not_part_of_valid_path(public_keys, None);
    if excluded_certs.is_empty() {
        return Ok(NO_EXCLUDED_CERTS_TEXT.to_string());
    }
    let display_text = MultiItemOutput::from_items(excluded_certs).format(format_method)?;
    Ok(display_text)
}

fn display_paths<R: Role>(
    all_paths: Vec<Vec<ChainItem<R>>>,
    method: &FormatMethod,
) -> Result<String, FormatError> {
    all_paths
        .into_iter()
        .enumerate()
        .map(|(index, path)| {
            let text = format!("Path {}:\n", index + 1);
            let formatted_path = MultiItemOutput::from_items(path).format(method)?;
            Ok(format!("{}{}", text, formatted_path))
        })
        .collect::<Result<String, FormatError>>()
}

/// A trait for types that support multiple formatting options for use in the CLI inspection tools.
pub trait Formattable: Digestible {
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

/// Container for the output of the CLI inspection tools.
/// Holds a single certificate or token request.
#[derive(Serialize)]
#[serde(transparent)]
pub struct SingleRequestOutput<T>(pub T);

impl<T: Digestible> Digestible for SingleRequestOutput<T> {
    type Digest = SingleItemDigest<T::Digest>;
}
impl<T: Digestible> Formattable for SingleRequestOutput<T> {}

#[derive(Serialize)]
#[serde(transparent)]
pub struct SingleItemDigest<T>(T);

impl<T: Digestible, K> From<SingleRequestOutput<T>> for SingleItemDigest<K>
where
    T: Digestible<Digest = K>,
{
    fn from(value: SingleRequestOutput<T>) -> Self {
        SingleItemDigest(value.0.into_digest())
    }
}

impl<T: Display> Display for SingleItemDigest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize)]
pub struct ItemWithError<T> {
    pub item: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ValidationError>,
}

/// Container for the output of the CLI inspection tools.
/// Capable of holding multiple certificates and tokens, and includes any associated validation errors.
#[derive(Serialize)]
#[serde(transparent)]
pub struct MultiItemOutput<R: Role>(Vec<ItemWithError<ChainItem<R>>>);

impl<R: Role> MultiItemOutput<R> {
    pub fn from_items<T: Into<ChainItem<R>>>(items: impl IntoIterator<Item = T>) -> Self {
        let items = items
            .into_iter()
            .map(|item| item.into())
            .map(|item| {
                let error = item.validate(None).err();
                ItemWithError { item, error }
            })
            .collect();
        Self(items)
    }
}

impl<R: Role> Formattable for MultiItemOutput<R> {}

/// Container for the digest output of the CLI inspection tools.
/// Capable of holding multiple certificates and tokens, and includes any associated validation errors.
#[derive(Serialize)]
#[serde(transparent)]
pub struct MultiItemDigestOutput(Vec<ItemWithError<ChainItemDigest>>);

impl<R: Role> From<MultiItemOutput<R>> for MultiItemDigestOutput {
    fn from(value: MultiItemOutput<R>) -> Self {
        MultiItemDigestOutput(
            value
                .0
                .into_iter()
                .map(|ItemWithError { item, error }| ItemWithError {
                    item: item.into(),
                    error,
                })
                .collect(),
        )
    }
}

impl<R: Role> Digestible for MultiItemOutput<R> {
    type Digest = MultiItemDigestOutput;
}

impl Display for MultiItemDigestOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut iter = self.0.iter().peekable();
        while let Some(ItemWithError { item, error }) = iter.next() {
            write!(f, "{}", item)?;
            if let Some(error) = &error {
                write!(f, "\n{}", error)?;
            }
            if iter.peek().is_some() {
                writeln!(f, "\n")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use certificates::test_helpers::{create_keyserver_token_bundle, BreakableSignature};
    use certificates::{ChainItem, ChainTraversal, Digestible, Infrastructure};
    use serde_json::Value;

    use crate::inspect::{FormatMethod, Formattable, MultiItemOutput};

    #[test]
    fn test_plaintext_digest_display_for_certs_and_tokens() {
        let items = create_multiple_items_with_one_invalid_signature();

        let text = MultiItemOutput::from_items(items.clone())
            .format(&FormatMethod::PlainDigest)
            .unwrap();
        let expected_text = format!(
            "{}\nINVALID: The signature failed verification\n\n{}\n\n{}",
            items[0].clone().into_digest(),
            items[1].clone().into_digest(),
            items[2].clone().into_digest(),
        );
        assert_eq!(text, expected_text);
    }

    #[test]
    fn test_json_digest_display_for_certs_and_tokens() {
        let items = create_multiple_items_with_one_invalid_signature();

        let text = MultiItemOutput::from_items(items.clone())
            .format(&FormatMethod::JsonDigest)
            .unwrap();

        let json = serde_json::from_str::<Value>(&text).unwrap();

        assert_eq!(&json[0]["error"]["causes"][0], "SignatureFailure");
        assert!(json[1].get("error").is_none());
        assert!(json[2].get("error").is_none());
    }

    fn create_multiple_items_with_one_invalid_signature() -> Vec<ChainItem<Infrastructure>> {
        let (token_bundle, _) = create_keyserver_token_bundle();
        let mut items = token_bundle.chain().into_iter().collect::<Vec<_>>();
        let mut token = token_bundle.token;
        token.break_signature();
        items.insert(0, token.into());
        items
    }
}
