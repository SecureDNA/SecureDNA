// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for generating a keypair for use with certificates and tokens
use std::{
    io::Write,
    path::{Path, PathBuf},
};

use clap::{crate_version, Parser};

use super::error::CertCliError;
use crate::common::create_new_key_file;
use crate::common::NewKeyDetails;
use crate::passphrase_reader::{PassphraseReader, PassphraseSource, ENV_PASSPHRASE_WARNING};

#[derive(Debug, Parser)]
#[clap(
name = "sdna-create-key",
about = "Generates a SecureDNA keypair",
version = crate_version!()
)]
pub struct CreateKeyOpts {
    #[clap(
        long,
        help = "Filepath where the keypair will be saved (optional). If this is not provided ~/SecureDNA will be used"
    )]
    pub output: Option<PathBuf>,
}

pub fn main<P, W, E>(
    opts: &CreateKeyOpts,
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
        Ok(NewKeyDetails {
            priv_path,
            pub_path,
            passphrase_source,
        }) => {
            if passphrase_source == PassphraseSource::EnvVar {
                writeln!(stderr, "{}", &*ENV_PASSPHRASE_WARNING)?;
            }
            writeln!(stdout, "Saved private key to {}", priv_path.display())?;
            writeln!(stdout, "Saved public key to {}", pub_path.display())
        }
        Err(err) => writeln!(stderr, "{err}"),
    }
}

fn run<P: PassphraseReader>(
    opts: &CreateKeyOpts,
    passphrase_reader: &P,
    default_directory: &Path,
) -> Result<NewKeyDetails, CertCliError> {
    let (_, details) = create_new_key_file(
        opts.output.as_ref(),
        passphrase_reader,
        default_directory,
        default_directory,
    )?;

    Ok(details)
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::common::NewKeyDetails;
    use crate::passphrase_reader::{
        EnvVarPassphraseReader, MemoryPassphraseReader, PassphraseReaderError, PassphraseSource,
        ENV_PASSPHRASE_WARNING, KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
    };
    use certificates::file::{KEY_PRIV_EXT, KEY_PUB_EXT};
    use tempfile::TempDir;

    use crate::shims::create_key::{self, CreateKeyOpts};
    use crate::shims::error::CertCliError;

    #[test]
    fn default_directory_is_created_if_not_present() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = default_dir.join("key.priv");

        let opts = CreateKeyOpts {
            output: Some(key_path.clone()),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_key::run(&opts, &passphrase_reader, &default_dir).expect("could not create keypair");

        assert!(default_dir.exists());
    }

    #[test]
    fn default_directory_is_not_created_if_not_required() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        let opts = CreateKeyOpts {
            output: Some(key_path.clone()),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_key::run(&opts, &passphrase_reader, &default_dir).expect("could not create keypair");

        assert!(!default_dir.exists());
    }

    #[test]
    fn if_no_key_destination_provided_default_is_used() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");

        let opts = CreateKeyOpts { output: None };

        let passphrase_reader = MemoryPassphraseReader::default();

        let NewKeyDetails {
            priv_path,
            pub_path,
            ..
        } = create_key::run(&opts, &passphrase_reader, &default_dir)
            .expect("could not create keypair");

        // Check the default directory is used.
        assert_eq!(priv_path.parent().unwrap(), default_dir);
        assert_eq!(pub_path.parent().unwrap(), default_dir);

        // Check the files exist.
        assert!(priv_path.exists(), "Private key destination does not exist");
        assert!(pub_path.exists(), "Public key destination does not exist");
    }

    #[test]
    fn existing_private_key_will_not_be_overwritten() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        File::create(&key_path).unwrap();

        let opts = CreateKeyOpts {
            output: Some(key_path.clone()),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_key::run(&opts, &passphrase_reader, &default_dir)
            .expect_err("should not save over existing key");
    }

    #[test]
    fn existing_public_key_will_not_be_overwritten() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        File::create(key_path.with_extension(KEY_PUB_EXT)).unwrap();

        let opts = CreateKeyOpts {
            output: Some(key_path.clone()),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_key::run(&opts, &passphrase_reader, &default_dir)
            .expect_err("should not save over existing key");
    }

    #[test]
    fn can_create_key_using_env_passphrase_reader() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        let opts = CreateKeyOpts {
            output: Some(key_path.clone()),
        };

        let passphrase_reader = EnvVarPassphraseReader;
        let test_passphrase = "test_passphrase";

        let key_details = temp_env::with_var(
            KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
            Some(test_passphrase),
            || create_key::run(&opts, &passphrase_reader, &default_dir),
        )
        .unwrap();

        let expected = NewKeyDetails {
            pub_path: key_path.with_extension(KEY_PUB_EXT),
            priv_path: key_path,
            passphrase_source: PassphraseSource::EnvVar,
        };
        assert_eq!(key_details, expected);
    }

    #[test]
    fn warning_printed_to_stderr_on_creating_key_using_env_passphrase_reader() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        let opts = CreateKeyOpts {
            output: Some(key_path),
        };

        let passphrase_reader = EnvVarPassphraseReader;
        let test_passphrase = "test_passphrase";

        let mut stdout = vec![];
        let mut stderr = vec![];

        temp_env::with_var(
            KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
            Some(test_passphrase),
            || {
                create_key::main(
                    &opts,
                    passphrase_reader,
                    &default_dir,
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
    fn creating_key_using_env_passphrase_reader_fails_gracefully_if_env_variable_not_present() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        let opts = CreateKeyOpts {
            output: Some(key_path.clone()),
        };

        let passphrase_reader = EnvVarPassphraseReader;

        let err = temp_env::with_var_unset(KEY_ENCRYPTION_PASSPHRASE_ENV_VAR, || {
            create_key::run(&opts, &passphrase_reader, &default_dir)
        })
        .expect_err("expected an error when no env var present");

        assert!(!key_path.exists());
        assert_eq!(
            err,
            CertCliError::CouldNotReadPassphrase(PassphraseReaderError::EnvVariableNotFound)
        )
    }

    #[test]
    fn if_correct_extension_is_present_no_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        let opts = CreateKeyOpts {
            output: Some(key_path.clone()),
        };

        let key_details =
            create_key::run(&opts, &MemoryPassphraseReader::default(), &default_dir).unwrap();

        let expected = NewKeyDetails {
            pub_path: key_path.with_extension(KEY_PUB_EXT),
            priv_path: key_path,
            passphrase_source: PassphraseSource::Memory,
        };
        assert_eq!(key_details, expected);
    }

    #[test]
    fn if_no_extension_is_present_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key");

        let opts = CreateKeyOpts {
            output: Some(key_path.clone()),
        };

        let key_details =
            create_key::run(&opts, &MemoryPassphraseReader::default(), &default_dir).unwrap();

        let expected = NewKeyDetails {
            pub_path: key_path.with_extension(KEY_PUB_EXT),
            priv_path: key_path.with_extension(KEY_PRIV_EXT),
            passphrase_source: PassphraseSource::Memory,
        };
        assert_eq!(key_details, expected);
    }
}
