// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for encrypting and decrypting data using ECIES
use std::{
    io::Write,
    path::{Path, PathBuf},
};

use certificates::{
    bytes_from_pem, bytes_to_pem, encrypt_for_recipient,
    file::{
        KEY_PRIV_EXT, load_audit_keypair_from_file, load_audit_public_key_from_file,
        save_audit_keypair_to_file,
    },
    key::ecies::EciesKeyPair,
};
use clap::{Parser, crate_version};

use super::error::CertCliError;
use crate::passphrase_reader::PassphraseReader;
use crate::{default_filepath::get_default_filename_for_audit_key, key::NewKeyDetails};
use crate::{
    default_filepath::set_appropriate_filepath_and_create_default_dir_if_required,
    passphrase_reader::{
        CREATE_AUDIT_KEY_PASSPHRASE_PROMPT, ENTER_PASSPHRASE_PROMPT,
        PromptExistingPassphraseReader, PromptNewPassphraseReader,
    },
};

pub const ENCRYPTED_SCREENING_RESPONSE_TAG: &str = "SECUREDNA ENCRYPTED SCREENING RESPONSE";

#[derive(Debug, Parser)]
#[clap(
name = "sdna-audit",
about = "Functionality for encrypting and decrypting screening results for auditing",
version = crate_version!()
)]
pub struct AuditOpts {
    #[clap(subcommand)]
    pub command: AuditCommand,
}

#[derive(Debug, Parser)]
pub enum AuditCommand {
    #[clap(
        name = "create-key",
        about = "Create a new key to be used for decrypting data"
    )]
    CreateKey {
        #[clap(
            long,
            help = "Filepath where the decryption key will be saved (optional). If this is not provided ~/SecureDNA will be used"
        )]
        output: Option<PathBuf>,
    },
    #[clap(
        name = "encrypt",
        about = "Encrypt data for a recipient who owns a specific key"
    )]
    Encrypt {
        #[clap(long, help = "Path to the public key file of the intended recipient")]
        public_key: PathBuf,
        #[clap(long, help = "Path to the input file which is to be encrypted")]
        input: PathBuf,
        #[clap(long, help = "Path to save the encrypted output")]
        output: Option<PathBuf>,
    },
    #[clap(name = "decrypt", about = "Decrypt data using a private key")]
    Decrypt {
        #[clap(
            long,
            help = "Path to the private key file which will decrypt the data"
        )]
        private_key: PathBuf,
        #[clap(long, help = "Path to the encrypted input file")]
        input: PathBuf,
        #[clap(long, help = "Path to save the decrypted output")]
        output: Option<PathBuf>,
    },
}

pub fn main<W, E>(
    opts: &AuditOpts,
    default_directory: &Path,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<(), std::io::Error>
where
    W: Write,
    E: Write,
{
    match &opts.command {
        AuditCommand::CreateKey { output } => {
            let passphrase_reader =
                PromptNewPassphraseReader::new(CREATE_AUDIT_KEY_PASSPHRASE_PROMPT);
            match run_create_key(output.as_ref(), &passphrase_reader, default_directory) {
                Ok(NewKeyDetails {
                    priv_path,
                    pub_path,
                    ..
                }) => {
                    writeln!(stdout, "Saved private key to {}", priv_path.display())?;
                    writeln!(stdout, "Saved public key to {}", pub_path.display())
                }
                Err(err) => writeln!(stderr, "{err}"),
            }
        }
        AuditCommand::Encrypt {
            public_key,
            input,
            output,
        } => match run_encrypt(public_key, input, output.as_ref(), default_directory) {
            Ok(output) => writeln!(
                stdout,
                "The data was successfully encrypted and saved to {}",
                output.display()
            ),
            Err(err) => writeln!(stderr, "{err}"),
        },
        AuditCommand::Decrypt {
            private_key,
            input,
            output,
        } => {
            let passphrase_reader = PromptExistingPassphraseReader::new(ENTER_PASSPHRASE_PROMPT);
            match run_decrypt(
                private_key,
                input,
                output.as_ref(),
                &passphrase_reader,
                default_directory,
            ) {
                Ok(output) => writeln!(
                    stdout,
                    "The data was successfully decrypted and saved to {}",
                    output.display()
                ),
                Err(err) => writeln!(stderr, "{err}"),
            }
        }
    }
}

fn run_create_key<P: PassphraseReader>(
    output: Option<&PathBuf>,
    passphrase_reader: &P,
    default_directory: &Path,
) -> Result<NewKeyDetails, CertCliError> {
    let (passphrase, passphrase_source) = passphrase_reader
        .read_passphrase()
        .map_err(CertCliError::from)?;

    let keypair = EciesKeyPair::new_random();

    let key_path = set_appropriate_filepath_and_create_default_dir_if_required(
        output,
        KEY_PRIV_EXT,
        || default_directory.join(get_default_filename_for_audit_key(&keypair.public_key())),
        default_directory,
    )?;

    let (priv_path, pub_path) = save_audit_keypair_to_file(keypair, passphrase, &key_path)?;

    Ok(NewKeyDetails {
        priv_path,
        pub_path,
        passphrase_source,
    })
}

fn run_encrypt(
    public_key: &Path,
    input: &Path,
    output: Option<&PathBuf>,
    default_directory: &Path,
) -> Result<PathBuf, CertCliError> {
    let to_encrypt = std::fs::read(input)
        .map_err(|err| CertCliError::PlaintextFileRead(input.to_path_buf(), err.to_string()))?;
    let pk_contents = load_audit_public_key_from_file(public_key)?;

    let encrypted = encrypt_for_recipient(&pk_contents, &to_encrypt)
        .map_err(|_| CertCliError::DataEncryptionFailed)?;
    let pem = bytes_to_pem(&encrypted, ENCRYPTED_SCREENING_RESPONSE_TAG);

    let output = set_appropriate_filepath_and_create_default_dir_if_required(
        output,
        "txt",
        || default_directory.join("encrypted.txt"),
        default_directory,
    )?;
    std::fs::write(&output, pem)
        .map_err(|err| CertCliError::EncryptionOutputFileWrite(output.clone(), err.to_string()))?;
    Ok(output)
}

fn run_decrypt<P: PassphraseReader>(
    private_key_path: &Path,
    input: &Path,
    output: Option<&PathBuf>,
    passphrase_reader: &P,
    default_directory: &Path,
) -> Result<PathBuf, CertCliError> {
    let (passphrase, _) = passphrase_reader.read_passphrase()?;
    let kp = load_audit_keypair_from_file(private_key_path, passphrase)?;

    let pem = std::fs::read_to_string(input)
        .map_err(|err| CertCliError::EncryptedDataFileRead(input.to_path_buf(), err.to_string()))?;
    let encrypted = bytes_from_pem(&pem, ENCRYPTED_SCREENING_RESPONSE_TAG.to_string())
        .map_err(|_| CertCliError::UnexpectedAuditFileContents)?;

    let decrypted = kp
        .decrypt(encrypted)
        .map_err(|_| CertCliError::DataDecryptionFailed)?;
    let output = set_appropriate_filepath_and_create_default_dir_if_required(
        output,
        "txt",
        || default_directory.join("decrypted.txt"),
        default_directory,
    )?;
    std::fs::write(&output, decrypted)
        .map_err(|err| CertCliError::DecryptionOutputFileWrite(output.clone(), err.to_string()))?;
    Ok(output)
}

#[cfg(all(test, feature = "cert_tests"))]
mod tests {
    use tempfile::TempDir;

    use crate::passphrase_reader::MemoryPassphraseReader;

    use super::*;

    #[test]
    fn can_create_audit_key() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let output = temp_path.join("key.priv");

        let passphrase_reader = MemoryPassphraseReader::default();
        let new_key_details = run_create_key(Some(&output), &passphrase_reader, temp_path).unwrap();

        assert_eq!(new_key_details.priv_path, output);
        assert_eq!(new_key_details.pub_path, output.with_extension("pub"));

        load_audit_keypair_from_file(&new_key_details.priv_path, passphrase_reader.passphrase)
            .expect("unable to load keypair created by audit CLI");
    }

    #[test]
    fn encrypted_file_contains_expected_pem_header() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let key_path = temp_path.join("key.priv");
        let input = temp_path.join("input.txt");
        let output = temp_path.join("encrypted.txt");

        let plaintext = b"Hello, world!";
        std::fs::write(&input, plaintext).unwrap();

        let kp = EciesKeyPair::new_random();
        save_audit_keypair_to_file(kp, "passphrase", &key_path).unwrap();

        run_encrypt(
            &key_path.with_extension("pub"),
            &input,
            Some(&output),
            temp_path,
        )
        .unwrap();

        let pem = std::fs::read_to_string(&output).unwrap();
        let expected = format!("-----BEGIN {}-----", ENCRYPTED_SCREENING_RESPONSE_TAG);
        assert!(pem.contains(&expected));
    }

    #[test]
    fn can_encrypt_using_audit_cli_tool() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let key_path = temp_path.join("key.priv");
        let input = temp_path.join("input.txt");
        let output = temp_path.join("encrypted.txt");

        let plaintext = b"Hello, world!";
        std::fs::write(&input, plaintext).unwrap();

        let kp = EciesKeyPair::new_random();
        save_audit_keypair_to_file(kp.clone(), "passphrase", &key_path).unwrap();

        run_encrypt(
            &key_path.with_extension("pub"),
            &input,
            Some(&output),
            temp_path,
        )
        .unwrap();

        let pem = std::fs::read(&output).unwrap();
        let encrypted = bytes_from_pem(&pem, ENCRYPTED_SCREENING_RESPONSE_TAG.to_string()).unwrap();
        let decrypted = kp.decrypt(encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn can_decrypt_using_audit_cli_tool() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let key_path = temp_path.join("key.priv");
        let input = temp_path.join("encrypted.txt");
        let output = temp_path.join("decrypted.txt");

        let plaintext = b"Hello, world!";

        let kp = EciesKeyPair::new_random();
        let encrypted = encrypt_for_recipient(&kp.public_key(), plaintext).unwrap();
        let pem = bytes_to_pem(&encrypted, ENCRYPTED_SCREENING_RESPONSE_TAG);
        std::fs::write(&input, pem).unwrap();

        let passphrase_reader = MemoryPassphraseReader::default();

        save_audit_keypair_to_file(kp.clone(), &passphrase_reader.passphrase, &key_path).unwrap();

        run_decrypt(
            &key_path,
            &input,
            Some(&output),
            &passphrase_reader,
            temp_path,
        )
        .unwrap();

        let decrypted_contents = std::fs::read(&output).unwrap();
        assert_eq!(decrypted_contents, plaintext);
    }
}
