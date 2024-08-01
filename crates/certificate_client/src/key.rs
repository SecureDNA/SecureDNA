// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::Parser;

use certificates::file::{KEY_PRIV_EXT, KEY_PUB_EXT};
use certificates::{
    file::{load_public_key_from_file, save_keypair_to_file},
    KeyPair, PublicKey,
};

use crate::default_filepath::set_appropriate_filepath_and_create_default_dir_if_required;
use crate::passphrase_reader::{PassphraseReader, PassphraseSource};
use crate::{default_filepath::get_default_filename_for_key, shims::error::CertCliError};

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
