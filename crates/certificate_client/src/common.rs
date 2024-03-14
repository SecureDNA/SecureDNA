// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::{Parser, Subcommand};

use certificates::file::{KEY_PRIV_EXT, KEY_PUB_EXT};
use certificates::{
    file::{load_public_key_from_file, save_keypair_to_file},
    format_multiple_items, ChainItem, ChainTraversal, FormatError, FormatMethod, KeyPair,
    PublicKey, Role,
};

use crate::default_filename::set_appropriate_filepath_and_create_default_dir_if_required;
use crate::passphrase_reader::{PassphraseReader, PassphraseSource};
use crate::{default_filename::get_default_filename_for_key, shims::error::CertCliError};

const DEFAULT_FOLDER: &str = "SecureDNA";

const NO_CHAIN_TEXT: &str = "This item has no certificate chain attached";

pub const NO_PATH_FOUND_TEXT: &str =
    "No valid path found to an issuing certificate with a matching public key";

pub const NO_EXCLUDED_CERTS_TEXT: &str = "No certificates found that were not part of a valid path";

pub fn cli_default_directory() -> Result<PathBuf, CertCliError> {
    let mut path = dirs::home_dir().ok_or(CertCliError::DefaultDirectoryPath)?;
    path.push(DEFAULT_FOLDER);
    Ok(path)
}

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
            ChainViewMode::AllCerts => display_all_certs_in_chain(bundle, method),
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

pub fn display_all_certs_in_chain<B: ChainTraversal>(
    bundle: B,
    format_method: &FormatMethod,
) -> Result<String, CertCliError> {
    let chain = bundle.chain();
    if chain.is_empty() {
        Ok(NO_CHAIN_TEXT.to_string())
    } else {
        let display_text = format_multiple_items(chain, format_method)?;
        Ok(display_text)
    }
}

pub fn display_all_valid_paths<B: ChainTraversal>(
    bundle: B,
    format_method: &FormatMethod,
    public_keys: &[PublicKey],
) -> Result<String, CertCliError> {
    let all_paths = bundle.find_all_paths_to_issuers(public_keys);
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
    let excluded_certs = bundle.find_items_not_part_of_valid_path(public_keys);
    if excluded_certs.is_empty() {
        return Ok(NO_EXCLUDED_CERTS_TEXT.to_string());
    }
    let display_text = format_multiple_items(excluded_certs, format_method)?;
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
            let formatted_path = format_multiple_items(path, method)?;
            Ok(format!("{}{}", text, formatted_path))
        })
        .collect::<Result<String, FormatError>>()
}

/// Options for adding an associated key to a certificate or token request
#[derive(Clone, Debug, Default, PartialEq, Parser)]
pub struct AssociatedKeyArgs {
    #[clap(
        long,
        help = "Filepath where the private key will be saved (optional). If this is not provided ~/SecureDNA will be used"
    )]
    create_new_key: Option<PathBuf>,
    #[clap(long, help = "Path to .pub file (optional)")]
    key_from_file: Option<PathBuf>,
    #[clap(
        long,
        help = "Hex representation of public key (optional, found inside the .pub file on the first line)"
    )]
    key_from_hex: Option<String>,
}

impl AssociatedKeyArgs {
    pub fn create_key_at_path(path: PathBuf) -> Self {
        Self {
            create_new_key: Some(path),
            key_from_file: None,
            key_from_hex: None,
        }
    }
    pub fn key_from_file(path: PathBuf) -> Self {
        Self {
            create_new_key: None,
            key_from_file: Some(path),
            key_from_hex: None,
        }
    }
    pub fn key_from_hex(hex: String) -> Self {
        Self {
            create_new_key: None,
            key_from_file: None,
            key_from_hex: Some(hex),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum AssociatedKey {
    CreateNewKey { output: Option<PathBuf> },
    KeyFromFile { path: PathBuf },
    KeyFromHex { hex: String },
}

impl TryFrom<AssociatedKeyArgs> for AssociatedKey {
    type Error = CertCliError;

    fn try_from(args: AssociatedKeyArgs) -> Result<Self, Self::Error> {
        match (args.create_new_key, args.key_from_file, args.key_from_hex) {
            (None, None, None) => Ok(AssociatedKey::CreateNewKey { output: None }),
            (Some(output), None, None) => Ok(AssociatedKey::CreateNewKey {
                output: Some(output),
            }),
            (None, Some(path), None) => Ok(AssociatedKey::KeyFromFile { path }),
            (None, None, Some(hex)) => Ok(AssociatedKey::KeyFromHex { hex }),
            _ => Err(CertCliError::TooManyKeyArgs),
        }
    }
}

impl AssociatedKey {
    pub fn process_key<P: PassphraseReader>(
        self,
        passphrase_reader: &P,
        directory: &Path, // directory used to save key if key path not provided
        default_directory: &Path,
    ) -> Result<(PublicKey, KeySource), CertCliError> {
        match self {
            Self::CreateNewKey { output } => {
                let (public_key, details) = create_new_key_file(
                    output.as_ref(),
                    passphrase_reader,
                    directory,
                    default_directory,
                )?;
                Ok((public_key, KeySource::NewKey(details)))
            }
            Self::KeyFromFile { path } => {
                let key_path = match path.extension() {
                    Some(_) => path,
                    None => path.with_extension(KEY_PUB_EXT),
                };
                let public_key = load_public_key_from_file(&key_path)?;
                Ok((public_key, KeySource::Preexisting))
            }
            Self::KeyFromHex { hex } => {
                let public_key =
                    PublicKey::from_str(&hex).map_err(|_| CertCliError::PublicKeyError)?;
                Ok((public_key, KeySource::Preexisting))
            }
        }
    }
}

pub fn create_new_key_file<P: PassphraseReader>(
    output: Option<&PathBuf>,
    passphrase_reader: &P,
    parent_directory: &Path,
    default_directory: &Path,
) -> Result<(PublicKey, NewKeyDetails), CertCliError> {
    let (passphrase, passphrase_source) = passphrase_reader
        .read_passphrase()
        .map_err(CertCliError::from)?;

    let keypair = KeyPair::new_random();

    let public_key = keypair.public_key();

    let key_path = set_appropriate_filepath_and_create_default_dir_if_required(
        output,
        KEY_PRIV_EXT,
        || parent_directory.join(get_default_filename_for_key(&keypair.public_key())),
        default_directory,
    )?;

    let (priv_path, pub_path) = save_keypair_to_file(keypair, passphrase, &key_path)?;
    Ok((
        public_key,
        NewKeyDetails {
            priv_path,
            pub_path,
            passphrase_source,
        },
    ))
}

#[derive(Debug, PartialEq)]
pub struct NewKeyDetails {
    pub priv_path: PathBuf,
    pub pub_path: PathBuf,
    pub passphrase_source: PassphraseSource,
}

#[derive(Debug, PartialEq)]
pub enum KeySource {
    Preexisting,
    NewKey(NewKeyDetails),
}
