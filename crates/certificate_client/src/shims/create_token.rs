// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for generating a new token request
use std::{
    io::Write,
    path::{Path, PathBuf},
};

use clap::{crate_version, Parser, Subcommand};

use doprf::party::KeyserverId;

use super::error::CertCliError;
use crate::default_filename::set_appropriate_filepath_and_create_default_dir_if_required;
use crate::{
    common::{AssociatedKey, AssociatedKeyArgs, KeySource, NewKeyDetails},
    default_filename::get_default_filename_for_token_request,
    passphrase_reader::{PassphraseReader, PassphraseSource, ENV_PASSPHRASE_WARNING},
};
use certificates::{
    file::{save_token_request_to_file, TokenExtension},
    AuditRecipient, DatabaseTokenGroup, DatabaseTokenRequest, HltTokenGroup, HltTokenRequest,
    KeyserverTokenGroup, KeyserverTokenRequest, PublicKey, SynthesizerTokenGroup,
    SynthesizerTokenRequest, TokenGroup,
};

#[derive(Debug, Parser)]
#[clap(
name = "sdna-create-token",
about = "Generates a SecureDNA token request",
version = crate_version!()
)]

pub struct CreateTokenOpts {
    #[clap(help = "Type of token [possible values: keyserver, database, synthesizer, hlt]")]
    #[clap(subcommand)]
    pub token: TokenArgs,
    #[clap(
        long,
        global = true,
        help = "Filepath where the token request will be saved (optional). If this is not provided ~/SecureDNA will be used"
    )]
    pub output: Option<PathBuf>,
    #[clap(flatten)]
    pub key: AssociatedKeyArgs,
}

#[derive(Debug, Subcommand, PartialEq)]
pub enum TokenArgs {
    ExemptionList,
    Keyserver {
        #[clap(
            long,
            help = "Keyserver ID, this corresponds to the index of the keyserver's keyshare"
        )]
        keyserver_id: KeyserverId,
    },
    Database,
    Hlt,
    Synthesizer {
        #[clap(long, help = "The domain name of the manufacturer")]
        domain: String,
        #[clap(long, help = "The machine model name or number")]
        model: String,
        #[clap(long, help = "The machine serial number")]
        serial: String,
        #[clap(
            long,
            help = "The expected maximum rate at which this machine can synthesize DNA, in nucleotides per day"
        )]
        rate_limit: u64,
        #[clap(long, help = "Email of the audit recipient")]
        audit_email: Option<String>,
        #[clap(long, help = "Public key of the audit recipient")]
        audit_public_key: Option<String>,
    },
}

pub fn main<P, W, E>(
    opts: &CreateTokenOpts,
    passphrase_reader: P,
    default_directory: &Path,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<(), std::io::Error>
where
    P: PassphraseReader,
    W: Write,
    E: Write,
{
    match run(opts, &passphrase_reader, default_directory) {
        Ok((request_path, key_source)) => {
            writeln!(
                stdout,
                "Saved new token request to {}",
                request_path.display()
            )?;
            if let KeySource::NewKey(NewKeyDetails {
                priv_path,
                pub_path,
                passphrase_source,
            }) = key_source
            {
                if passphrase_source == PassphraseSource::EnvVar {
                    writeln!(stderr, "{}", &*ENV_PASSPHRASE_WARNING)?;
                }
                writeln!(stdout, "Saved new private key to {}", priv_path.display())?;
                writeln!(stdout, "Saved new public key to {}", pub_path.display())?;
            };
            Ok(())
        }
        Err(err) => writeln!(stderr, "{err}"),
    }
}

fn run<P: PassphraseReader>(
    opts: &CreateTokenOpts,
    passphrase_reader: &P,
    default_directory: &Path,
) -> Result<(PathBuf, KeySource), CertCliError> {
    let (req_path, key_info) = match &opts.token {
        // Leaving as TODO for now due to complications of entering ELT fields via CLI
        // See https://github.com/SecureDNA/SecureDNA/issues/1342
        TokenArgs::ExemptionList {} => {
            todo!()
        }
        TokenArgs::Keyserver { keyserver_id } => {
            create_token_with_associated_keypair::<_, KeyserverTokenGroup, _>(
                opts,
                passphrase_reader,
                default_directory,
                |public_key| KeyserverTokenRequest::v1_token_request(public_key, *keyserver_id),
            )
        }
        TokenArgs::Database => create_token_with_associated_keypair::<_, DatabaseTokenGroup, _>(
            opts,
            passphrase_reader,
            default_directory,
            DatabaseTokenRequest::v1_token_request,
        ),
        TokenArgs::Hlt => create_token_with_associated_keypair::<_, HltTokenGroup, _>(
            opts,
            passphrase_reader,
            default_directory,
            HltTokenRequest::v1_token_request,
        ),
        TokenArgs::Synthesizer {
            domain,
            model,
            serial,
            rate_limit: max_dna_base_pairs_per_day,
            audit_email,
            audit_public_key,
        } => {
            let audit_recipient = match (audit_email, audit_public_key) {
                (None, None) => Ok(None),
                (Some(email), Some(public_key)) => AuditRecipient::new(email, public_key)
                    .map(Some)
                    .map_err(|_| CertCliError::AuditKeyParseError),
                (None, Some(_)) => Err(CertCliError::MissingAuditEmail),
                (Some(_), None) => Err(CertCliError::MissingAuditPublicKey),
            }?;

            create_token_with_associated_keypair::<_, SynthesizerTokenGroup, _>(
                opts,
                passphrase_reader,
                default_directory,
                |public_key| {
                    SynthesizerTokenRequest::v1_token_request(
                        public_key,
                        domain,
                        model,
                        serial,
                        *max_dna_base_pairs_per_day,
                        audit_recipient,
                    )
                },
            )
        }
    }?;
    Ok((req_path, key_info))
}

/// Can be used to create token requests that have an associated keypair.
/// Saves the token request and keypair to file.
fn create_token_with_associated_keypair<P, T, F>(
    opts: &CreateTokenOpts,
    passphrase_reader: &P,
    default_directory: &Path,
    create_req_fn: F,
) -> Result<(PathBuf, KeySource), CertCliError>
where
    P: PassphraseReader,
    T: TokenGroup + TokenExtension,
    F: FnOnce(PublicKey) -> T::TokenRequest,
{
    let key_opts: AssociatedKey = opts.key.clone().try_into()?;

    // If a file destination has been specified for the certificate request but not for the key
    // destination, we will derive the key destination directory from the request destination.
    // If neither have been set, both request and key files will be saved to default locations.
    let key_directory = opts
        .output
        .as_ref()
        .and_then(|path| path.parent())
        .unwrap_or(default_directory);

    let (public_key, key_source) =
        key_opts.process_key(passphrase_reader, key_directory, default_directory)?;

    let req = create_req_fn(public_key);

    // If the request destination has not been provided then we will use the default directory and a default filename.
    let request_path: PathBuf = set_appropriate_filepath_and_create_default_dir_if_required(
        opts.output.as_ref(),
        T::REQUEST_EXT,
        || default_directory.join(get_default_filename_for_token_request::<T>(&req)),
        default_directory,
    )?;

    save_token_request_to_file::<T>(req, &request_path)?;

    Ok::<_, CertCliError>((request_path, key_source))
}

#[cfg(test)]
mod tests {

    use crate::shims::create_token;

    use super::*;

    use crate::passphrase_reader::{
        EnvVarPassphraseReader, MemoryPassphraseReader, PassphraseReaderError,
        KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
    };
    use certificates::file::{KEYSERVER_TOKEN_REQUEST_EXT, KEY_PRIV_EXT, KEY_PUB_EXT};
    use certificates::{
        file::{load_keypair_from_file, load_token_request_from_file, save_public_key_to_file},
        KeyPair, TokenKind,
    };
    use tempfile::TempDir;

    #[test]
    fn token_request_and_key_saved_in_default_directory_if_destination_not_provided() {
        let default_directory = TempDir::new().unwrap();
        let pass_reader = MemoryPassphraseReader::default();

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: None,
            key: AssociatedKeyArgs::default(),
        };
        let (request_path, key_source) =
            create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        match key_source {
            KeySource::NewKey(NewKeyDetails {
                priv_path,
                pub_path,
                ..
            }) => {
                // Check the default directory is used.
                assert_eq!(request_path.parent().unwrap(), default_directory.path());
                assert_eq!(priv_path.parent().unwrap(), default_directory.path());
                assert_eq!(pub_path.parent().unwrap(), default_directory.path());

                // Check the files exist.
                assert!(request_path.exists(), "Request destination does not exist");
                assert!(priv_path.exists(), "Key destination does not exist");
                assert!(pub_path.exists(), "Key destination does not exist");
            }
            _ => panic!("Key not saved to file"),
        };
    }

    #[test]
    fn default_dir_is_created_if_not_present_where_no_output_paths_specified() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: None,
            key: AssociatedKeyArgs::default(),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_token::run(&opts, &passphrase_reader, &default_dir).unwrap();

        assert!(default_dir.exists())
    }

    #[test]
    fn default_dir_is_created_if_not_present_where_no_request_output_is_supplied() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: None,
            key: AssociatedKeyArgs::create_key_at_path(key_path),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_token::run(&opts, &passphrase_reader, &default_dir).unwrap();

        assert!(default_dir.exists())
    }

    #[test]
    fn default_dir_is_not_created_if_not_required() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("1234.ktr");
        let key_path = temp_path.join("key.priv");

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: Some(request_path),
            key: AssociatedKeyArgs::create_key_at_path(key_path),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_token::run(&opts, &passphrase_reader, &default_dir).unwrap();

        assert!(!default_dir.exists())
    }

    #[test]
    fn if_correct_extension_is_present_no_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("1234.ktr");
        let key_path = temp_path.join("key.priv");

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        let (actual_request_path, actual_key_source) =
            create_token::run(&opts, &passphrase_reader, &default_dir).unwrap();
        let expected_key_source = KeySource::NewKey(NewKeyDetails {
            pub_path: key_path.with_extension(KEY_PUB_EXT),
            priv_path: key_path,
            passphrase_source: PassphraseSource::Memory,
        });

        assert_eq!(expected_key_source, actual_key_source);
        assert_eq!(request_path, actual_request_path);
    }

    #[test]
    fn if_no_extension_is_present_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("1234");
        let key_path = temp_path.join("key");

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        let (actual_request_path, actual_key_source) =
            create_token::run(&opts, &passphrase_reader, &default_dir).unwrap();
        let expected_key_source = KeySource::NewKey(NewKeyDetails {
            pub_path: key_path.with_extension(KEY_PUB_EXT),
            priv_path: key_path.with_extension(KEY_PRIV_EXT),
            passphrase_source: PassphraseSource::Memory,
        });

        assert_eq!(expected_key_source, actual_key_source);
        assert_eq!(
            request_path.with_extension(KEYSERVER_TOKEN_REQUEST_EXT),
            actual_request_path
        );
    }

    #[test]
    fn token_request_key_destination_inferred_from_token_destination_when_not_provided() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.ktr");
        let pass_reader = MemoryPassphraseReader::default();

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::default(),
        };

        let (_, key_source) =
            create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        match key_source {
            KeySource::NewKey(NewKeyDetails {
                priv_path,
                pub_path,
                ..
            }) => {
                let expected_key_directory = request_path.parent().unwrap();

                assert_eq!(
                    priv_path.parent().unwrap(),
                    expected_key_directory,
                    "key destination not inferred correctly"
                );
                assert_eq!(
                    pub_path.parent().unwrap(),
                    expected_key_directory,
                    "key destination not inferred correctly"
                );
                assert!(priv_path.exists(), "key not saved to expected destination");
                assert!(pub_path.exists(), "key not saved to expected destination");
            }
            _ => panic!("Key not saved to file"),
        };
    }

    #[test]
    fn can_create_token_with_public_key_from_file() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.ktr");
        let pub_key_path = destination_directory.path().join("key.pub");

        let kp = KeyPair::new_random();
        save_public_key_to_file(kp.public_key(), &pub_key_path).unwrap();

        let pass_reader = MemoryPassphraseReader::default();

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::key_from_file(pub_key_path),
        };

        create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        assert!(request_path.exists());

        let request = load_token_request_from_file::<KeyserverTokenGroup>(&request_path).unwrap();
        assert_eq!(request.public_key(), &kp.public_key());
    }

    #[test]
    fn can_create_token_with_public_key_from_hex() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.ktr");

        let kp = KeyPair::new_random();
        let hex = kp.public_key().to_string();

        let pass_reader = MemoryPassphraseReader::default();

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::key_from_hex(hex),
        };

        create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        assert!(request_path.exists());

        let request = load_token_request_from_file::<KeyserverTokenGroup>(&request_path).unwrap();
        assert_eq!(request.public_key(), &kp.public_key());
    }

    #[test]
    fn can_create_token_request_using_env_passphrase_reader() {
        let default_dir = TempDir::new().unwrap();
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.dtr");
        let key_path = temp_dir.path().join("1234.priv");

        let opts = CreateTokenOpts {
            token: TokenArgs::Database,
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        let passphrase_reader = EnvVarPassphraseReader;
        let test_passphrase = "test_passphrase";

        let (path, key_source) = temp_env::with_var(
            KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
            Some(test_passphrase),
            || create_token::run(&opts, &passphrase_reader, default_dir.path()),
        )
        .unwrap();

        assert_eq!(path, request_path);
        assert!(request_path.exists());
        assert!(key_path.exists());
        assert!(
            matches!(key_source, KeySource::NewKey(NewKeyDetails {passphrase_source, ..}) if passphrase_source ==PassphraseSource::EnvVar)
        );

        // Check that key is retrievable with expected passphrase
        load_keypair_from_file(&key_path, test_passphrase)
            .expect("should be able to load saved key");
    }

    #[test]
    fn warning_printed_to_stderr_on_creating_token_request_using_env_passphrase_reader() {
        let default_dir = TempDir::new().unwrap();
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.dtr");
        let key_path = temp_dir.path().join("1234.priv");

        let opts = CreateTokenOpts {
            token: TokenArgs::Database,
            output: Some(request_path),
            key: AssociatedKeyArgs::create_key_at_path(key_path),
        };

        let passphrase_reader = EnvVarPassphraseReader;
        let test_passphrase = "test_passphrase";

        let mut stdout = vec![];
        let mut stderr = vec![];

        temp_env::with_var(
            KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
            Some(test_passphrase),
            || {
                create_token::main(
                    &opts,
                    passphrase_reader,
                    default_dir.path(),
                    &mut stdout,
                    &mut stderr,
                )
            },
        )
        .unwrap();

        let output = String::from_utf8_lossy(&stderr);
        assert!(output.contains(&*ENV_PASSPHRASE_WARNING));
    }

    #[test]
    fn create_token_request_using_env_passphrase_reader_fails_gracefully_if_env_var_not_present() {
        let default_dir = TempDir::new().unwrap();
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.dtr");
        let key_path = temp_dir.path().join("1234.priv");

        let opts = CreateTokenOpts {
            token: TokenArgs::Database,
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        let passphrase_reader = EnvVarPassphraseReader;

        let err = temp_env::with_var_unset(KEY_ENCRYPTION_PASSPHRASE_ENV_VAR, || {
            create_token::run(&opts, &passphrase_reader, default_dir.path())
        })
        .expect_err("expected an error when no env var present");

        assert!(!request_path.exists());
        assert!(!key_path.exists());
        assert_eq!(
            err,
            CertCliError::CouldNotReadPassphrase(PassphraseReaderError::EnvVariableNotFound)
        );
    }

    #[test]
    fn can_create_keyserver_token_request() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.ktr");
        let key_path = destination_directory.path().join("key.priv");
        let pass_reader = MemoryPassphraseReader::default();

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        assert!(request_path.exists());
        assert!(key_path.exists());

        let result = load_token_request_from_file::<KeyserverTokenGroup>(&request_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn can_create_database_token_request() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.dtr");
        let key_path = destination_directory.path().join("key.priv");
        let pass_reader = MemoryPassphraseReader::default();

        let opts = CreateTokenOpts {
            token: TokenArgs::Database {},
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        assert!(request_path.exists());
        assert!(key_path.exists());

        let result = load_token_request_from_file::<DatabaseTokenGroup>(&request_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn can_create_hlt_token_request() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.htr");
        let key_path = destination_directory.path().join("key.priv");
        let pass_reader = MemoryPassphraseReader::default();

        let opts = CreateTokenOpts {
            token: TokenArgs::Hlt,
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        assert!(request_path.exists());
        assert!(key_path.exists());

        let result = load_token_request_from_file::<HltTokenGroup>(&request_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn can_create_synthesizer_token_request() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.str");
        let key_path = destination_directory.path().join("key.priv");
        let pass_reader = MemoryPassphraseReader::default();

        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;

        let opts = CreateTokenOpts {
            token: TokenArgs::Synthesizer {
                domain,
                model,
                serial,
                rate_limit: max_dna_base_pairs_per_day,
                audit_email: None,
                audit_public_key: None,
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        assert!(request_path.exists());
        assert!(key_path.exists());

        let result = load_token_request_from_file::<SynthesizerTokenGroup>(&request_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn can_create_synthesizer_token_request_with_full_audit_details() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.str");
        let key_path = destination_directory.path().join("key.priv");
        let pass_reader = MemoryPassphraseReader::default();

        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;

        // Hex encoded libsecp256k1 key
        // Created via ecies::utils::generate_keypair()
        let audit_public_key =
            Some("03f29057c21d3eb14815eefa0127895b57278fd41c2bad78861ff7a5b1c9b5adae".to_string());

        let opts = CreateTokenOpts {
            token: TokenArgs::Synthesizer {
                domain,
                model,
                serial,
                rate_limit: max_dna_base_pairs_per_day,
                audit_email: Some("anna@example.com".to_string()),
                audit_public_key,
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        create_token::run(&opts, &pass_reader, default_directory.path()).unwrap();

        assert!(request_path.exists());
        assert!(key_path.exists());

        let result = load_token_request_from_file::<SynthesizerTokenGroup>(&request_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn cannot_create_synthesizer_token_request_with_non_parsable_audit_public_key() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.str");
        let key_path = destination_directory.path().join("key.priv");
        let pass_reader = MemoryPassphraseReader::default();

        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;

        let opts = CreateTokenOpts {
            token: TokenArgs::Synthesizer {
                domain,
                model,
                serial,
                rate_limit: max_dna_base_pairs_per_day,
                audit_email: Some("anna@example.com".to_string()),
                audit_public_key: Some("not a secp256k1 key".to_string()),
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        create_token::run(&opts, &pass_reader, default_directory.path())
            .expect_err("should not succeed with incorrect public key");
    }

    #[test]
    fn cannot_create_synthesizer_token_request_with_missing_audit_email() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.str");
        let key_path = destination_directory.path().join("key.priv");
        let pass_reader = MemoryPassphraseReader::default();

        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;

        let opts = CreateTokenOpts {
            token: TokenArgs::Synthesizer {
                domain,
                model,
                serial,
                rate_limit: max_dna_base_pairs_per_day,
                audit_email: None,
                audit_public_key: Some(
                    "03f29057c21d3eb14815eefa0127895b57278fd41c2bad78861ff7a5b1c9b5adae"
                        .to_string(),
                ),
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        create_token::run(&opts, &pass_reader, default_directory.path())
            .expect_err("should not succeed with partial audit details");
    }

    #[test]
    fn cannot_create_synthesizer_token_request_with_missing_audit_public_key() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.str");
        let key_path = destination_directory.path().join("key.priv");
        let pass_reader = MemoryPassphraseReader::default();

        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;

        let opts = CreateTokenOpts {
            token: TokenArgs::Synthesizer {
                domain,
                model,
                serial,
                rate_limit: max_dna_base_pairs_per_day,
                audit_email: Some("anna@example.com".to_string()),
                audit_public_key: None,
            },
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        create_token::run(&opts, &pass_reader, default_directory.path())
            .expect_err("should not succeed with partial audit details");
    }

    #[test]
    fn pub_key_extension_is_added_if_not_present() {
        let default_directory = TempDir::new().unwrap();
        let destination_directory = TempDir::new().unwrap();
        let request_path = destination_directory.path().join("token.ktr");
        let pub_key_path = destination_directory.path().join("key");

        let kp = KeyPair::new_random();
        save_public_key_to_file(kp.public_key(), &pub_key_path.with_extension(KEY_PUB_EXT))
            .unwrap();

        let pass_reader = MemoryPassphraseReader::default();

        let opts = CreateTokenOpts {
            token: TokenArgs::Keyserver {
                keyserver_id: KeyserverId::try_from(1).unwrap(),
            },
            output: Some(request_path),
            key: AssociatedKeyArgs::key_from_file(pub_key_path),
        };

        create_token::run(&opts, &pass_reader, default_directory.path())
            .expect("should have inferred .pub key extension");
    }

    // We want to check for consistency here because TokenKind is used in other CLI tools
    #[test]
    fn token_kind_and_token_args_have_consistent_parsing() {
        let test_cases = vec![
            (
                vec!["exemption-list"],
                TokenKind::ExemptionList,
                TokenArgs::ExemptionList {},
            ),
            (
                vec!["keyserver", "--keyserver-id", "5"],
                TokenKind::Keyserver,
                TokenArgs::Keyserver {
                    keyserver_id: KeyserverId::try_from(5).unwrap(),
                },
            ),
            (vec!["database"], TokenKind::Database, TokenArgs::Database),
            (vec!["hlt"], TokenKind::Hlt, TokenArgs::Hlt),
            (
                vec![
                    "synthesizer",
                    "--domain",
                    "example.com",
                    "--model",
                    "XYZ123",
                    "--serial",
                    "45678",
                    "--rate-limit",
                    "10000",
                    "--audit-email",
                    "anna@example.com",
                    "--audit-public-key",
                    "03f29057c21d3eb14815eefa0127895b57278fd41c2bad78861ff7a5b1c9b5adae",
                ],
                TokenKind::Synthesizer,
                TokenArgs::Synthesizer {
                    domain: "example.com".to_string(),
                    model: "XYZ123".to_string(),
                    serial: "45678".to_string(),
                    rate_limit: 10000,
                    audit_email: Some("anna@example.com".to_string()),
                    audit_public_key: Some(
                        "03f29057c21d3eb14815eefa0127895b57278fd41c2bad78861ff7a5b1c9b5adae"
                            .to_string(),
                    ),
                },
            ),
        ];

        for (cli_args, expected_kind, expected_args) in test_cases {
            // Parse the first arg as TokenKind
            let parsed_kind = cli_args[0]
                .parse::<TokenKind>()
                .expect("Failed to parse TokenKind");

            assert_eq!(
                parsed_kind, expected_kind,
                "Mismatch in parsed TokenKind for input '{}'",
                cli_args[0]
            );

            // Parse as TokenArgs
            let parsed_type =
                parse_token_args(cli_args.clone()).expect("Failed to parse TokenArgs");

            assert_eq!(
                parsed_type, expected_args,
                "Mismatch in parsed TokenArgs for input '{:?}'",
                cli_args
            );
        }
    }

    #[derive(Parser, Debug)]
    struct MockParentCommand {
        #[clap(subcommand)]
        token: TokenArgs,
    }

    // This is a bit hacky but there doesn't seem to be a better way of parsing TokenArgs
    fn parse_token_args<'a, I>(args: I) -> Result<TokenArgs, clap::Error>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let complete_args = std::iter::once("mock_program").chain(args);

        let mock_command = MockParentCommand::try_parse_from(complete_args)?;
        Ok(mock_command.token)
    }
}
