// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for using a certificate to sign another certificate, or self-signing a root certificate request

use std::path::Path;
use std::{io::Write, path::PathBuf};

use crate::default_filename::set_appropriate_filepath_and_create_default_dir_if_required;
use certificates::file::{
    load_certificate_bundle_from_file, load_keypair_from_file, load_token_request_from_file,
    save_token_bundle_to_file, TokenExtension, CERT_EXT, KEY_PRIV_EXT,
};
use certificates::{
    Certificate, DatabaseTokenGroup, Expiration, HltTokenGroup, IssuanceError, KeyAvailable,
    KeyserverTokenGroup, SynthesizerTokenGroup, TokenBundle, TokenGroup, TokenKind,
};
use clap::{crate_version, Parser};

use crate::passphrase_reader::{PassphraseReader, PassphraseSource, ENV_PASSPHRASE_WARNING};

use super::error::CertCliError;

#[derive(Debug, Parser)]
#[clap(
    name = "sdna-sign-token",
    about = "Signs a SecureDNA token request",
    version = crate_version!()
)]
pub struct SignTokenOpts {
    #[clap(help = "Type of token [possible values: keyserver, database, synthesizer, hlt]")]
    pub token_type: TokenKind,
    #[clap(help = "Filepath where token request can be found")]
    pub token_request: PathBuf,
    #[clap(help = "Filepath where issuing certificate can be found.")]
    pub cert: PathBuf,
    #[clap(
        long,
        help = "Filepath where issuer's private key can be found (optional). If this is not provided, an attempt will be made to infer it by using the filepath of the certificate"
    )]
    pub key: Option<PathBuf>,
    #[clap(
        long,
        help = "How many days after today the certificate will be valid for (optional, default is 28)"
    )]
    pub days_valid: Option<i64>,
    #[clap(
        long,
        help = "Filepath where new token will be saved (optional). If this is not provided it will be derived from the request filepath"
    )]
    pub output: Option<PathBuf>,
}

pub fn main<P: PassphraseReader, W: Write, E: Write>(
    opts: &SignTokenOpts,
    passphrase_reader: P,
    default_directory: &Path,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<(), std::io::Error> {
    match run(opts, passphrase_reader, default_directory) {
        Ok((filepath, passphrase_source)) => {
            if passphrase_source == PassphraseSource::EnvVar {
                writeln!(stderr, "{}", &*ENV_PASSPHRASE_WARNING)?;
            }
            writeln!(
                stdout,
                "A newly issued token has been saved to {}",
                filepath.display()
            )
        }
        Err(err) => writeln!(stderr, "{err}"),
    }
}

fn run<P: PassphraseReader>(
    opts: &SignTokenOpts,
    passphrase_reader: P,
    default_directory: &Path,
) -> Result<(PathBuf, PassphraseSource), CertCliError> {
    let expiration = opts
        .days_valid
        .map_or_else(|| Ok(Expiration::default()), Expiration::expiring_in_days)?;

    let key_path = opts
        .key
        .clone()
        .unwrap_or_else(|| opts.cert.with_extension(KEY_PRIV_EXT));

    match opts.token_type {
        // Leaving as TODO for now
        // See https://github.com/SecureDNA/SecureDNA/issues/1342
        TokenKind::ExemptionList => {
            todo!()
        }
        TokenKind::Keyserver => issue_token::<_, KeyserverTokenGroup, _>(
            opts,
            passphrase_reader,
            &key_path,
            |cert, req| cert.issue_keyserver_token(req, expiration),
            default_directory,
        ),
        TokenKind::Database => issue_token::<_, DatabaseTokenGroup, _>(
            opts,
            passphrase_reader,
            &key_path,
            |cert, req| cert.issue_database_token(req, expiration),
            default_directory,
        ),
        TokenKind::Hlt => issue_token::<_, HltTokenGroup, _>(
            opts,
            passphrase_reader,
            &key_path,
            |cert, req| cert.issue_hlt_token(req, expiration),
            default_directory,
        ),
        TokenKind::Synthesizer => issue_token::<_, SynthesizerTokenGroup, _>(
            opts,
            passphrase_reader,
            &key_path,
            |cert, req| cert.issue_synthesizer_token(req, expiration),
            default_directory,
        ),
    }
}

fn issue_token<P, T, F>(
    opts: &SignTokenOpts,
    passphrase_reader: P,
    key_path: &Path,
    token_issuer: F,
    default_directory: &Path,
) -> Result<(PathBuf, PassphraseSource), CertCliError>
where
    P: PassphraseReader,
    T: TokenGroup + TokenExtension,
    F: FnOnce(
        Certificate<T::AssociatedRole, KeyAvailable>,
        T::TokenRequest,
    ) -> Result<T::Token, IssuanceError>,
{
    let cert = match opts.cert.extension() {
        Some(_) => opts.cert.to_owned(),
        None => opts.cert.with_extension(CERT_EXT),
    };
    let issuing_cb = load_certificate_bundle_from_file::<T::AssociatedRole>(&cert)?;

    let (cert_passphrase, passphrase_source) = passphrase_reader
        .read_passphrase()
        .map_err(CertCliError::from)?;

    let key_path = match key_path.extension() {
        Some(_) => key_path.to_owned(),
        None => key_path.with_extension(KEY_PRIV_EXT),
    };
    let keypair = load_keypair_from_file(&key_path, cert_passphrase)?;

    let issuing_cert = issuing_cb
        .get_lead_cert()
        .map_err(|_| CertCliError::NoSuitableCertificate)?
        .to_owned()
        .load_key(keypair)?;

    let request_file = match opts.token_request.extension() {
        Some(_) => opts.token_request.to_owned(),
        None => opts.token_request.with_extension(T::REQUEST_EXT),
    };
    let request = load_token_request_from_file::<T>(&request_file)?;
    let token = token_issuer(issuing_cert, request)?;
    let chain = issuing_cb.issue_chain();
    let token_bundle = TokenBundle::<T>::new(token, chain);

    // If no path is provided for token destination we will derive it from the token request filepath.
    let token_path = set_appropriate_filepath_and_create_default_dir_if_required(
        opts.output.as_ref(),
        T::TOKEN_EXT,
        || opts.token_request.with_extension(T::TOKEN_EXT),
        default_directory,
    )?;

    save_token_bundle_to_file(token_bundle, &token_path)?;

    Ok((token_path, passphrase_source))
}

#[cfg(test)]
mod test {
    use certificates::file::{TokenExtension, CERT_EXT, KEYSERVER_TOKEN_EXT, KEY_PRIV_EXT};
    use certificates::key_traits::{CanLoadKey, HasAssociatedKey, KeyLoaded};
    use certificates::{
        file::{
            load_token_bundle_from_file, save_certificate_bundle_to_file, save_keypair_to_file,
            save_token_request_to_file,
        },
        test_helpers::create_leaf_bundle,
        ChainTraversal, DatabaseTokenGroup, DatabaseTokenRequest, Exemption, HltTokenGroup,
        HltTokenRequest, Infrastructure, KeyPair, KeyserverTokenGroup, KeyserverTokenRequest,
        Manufacturer, SynthesizerTokenGroup, SynthesizerTokenRequest, TokenKind,
    };
    use doprf::party::KeyserverId;
    use tempfile::TempDir;

    use crate::passphrase_reader::{
        EnvVarPassphraseReader, MemoryPassphraseReader, PassphraseReaderError,
        ENV_PASSPHRASE_WARNING, KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
    };
    use crate::shims::{
        error::CertCliError,
        sign_token::{self, SignTokenOpts},
    };

    #[test]
    fn can_sign_token_request_using_env_passphrase_reader() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let cert_path = temp_dir.path().join("leaf.cert");
        let request_path = temp_dir.path().join("db.dtr");
        let token_path = temp_dir.path().join("db.dt");
        let key_path = temp_dir.path().join("key.priv");

        let test_passphrase = "test_passphrase";

        let (leaf_bundle, keypair, _) = create_leaf_bundle::<Infrastructure>();
        save_keypair_to_file(keypair, test_passphrase, &key_path).unwrap();

        save_certificate_bundle_to_file(leaf_bundle, &cert_path).unwrap();

        let kp = KeyPair::new_random();
        let request = DatabaseTokenRequest::v1_token_request(kp.public_key());

        save_token_request_to_file::<DatabaseTokenGroup>(request, &request_path).unwrap();

        let opts = SignTokenOpts {
            token_type: TokenKind::Database,
            token_request: request_path,
            cert: cert_path,
            key: Some(key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        let passphrase_reader = EnvVarPassphraseReader;

        let mut stdout = vec![];
        let mut stderr = vec![];

        temp_env::with_var(
            KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
            Some(test_passphrase),
            || {
                sign_token::main(
                    &opts,
                    passphrase_reader,
                    &default_dir,
                    &mut stdout,
                    &mut stderr,
                )
            },
        )
        .unwrap();

        assert!(token_path.exists());

        let output = String::from_utf8_lossy(&stderr);
        assert!(output.contains(ENV_PASSPHRASE_WARNING.trim()));
    }

    #[test]
    fn sign_token_request_using_env_passphrase_reader_fails_gracefully_if_not_env_var_present() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let cert_path = temp_dir.path().join("leaf.cert");
        let request_path = temp_dir.path().join("db.dtr");
        let token_path = temp_dir.path().join("db.dt");
        let key_path = temp_dir.path().join("key.priv");

        let test_passphrase = "test_passphrase";

        let (leaf_bundle, keypair, _) = create_leaf_bundle::<Infrastructure>();
        save_keypair_to_file(keypair, test_passphrase, &key_path).unwrap();

        save_certificate_bundle_to_file(leaf_bundle, &cert_path).unwrap();

        let kp = KeyPair::new_random();
        let request = DatabaseTokenRequest::v1_token_request(kp.public_key());

        save_token_request_to_file::<DatabaseTokenGroup>(request, &request_path).unwrap();

        let opts = SignTokenOpts {
            token_type: TokenKind::Database,
            token_request: request_path,
            cert: cert_path,
            key: Some(key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        let passphrase_reader = EnvVarPassphraseReader;

        let err = temp_env::with_var_unset(KEY_ENCRYPTION_PASSPHRASE_ENV_VAR, || {
            sign_token::run(&opts, passphrase_reader, &default_dir)
        })
        .expect_err(
            "sign token should not succeed when using env passphrase reader with env var unset",
        );

        assert!(!token_path.exists());
        assert_eq!(
            err,
            CertCliError::CouldNotReadPassphrase(PassphraseReaderError::EnvVariableNotFound)
        )
    }

    #[test]
    fn default_dir_is_created_if_not_present_and_required_for_output() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        let request_path = temp_path.join("token.ktr");
        let token_path = default_dir.join("token.kt");

        let pass_reader = MemoryPassphraseReader::default();

        // Create infrastructure leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        assert!(default_dir.exists())
    }

    #[test]
    fn default_dir_is_not_created_if_not_required() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        let request_path = temp_path.join("token.ktr");
        let token_path = temp_path.join("token.kt");

        let pass_reader = MemoryPassphraseReader::default();

        // Create infrastructure leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        assert!(!default_dir.exists())
    }

    #[test]
    fn if_correct_extension_is_present_no_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        let request_path = temp_path.join("token.ktr");
        let token_path = temp_path.join("token.kt");

        let pass_reader = MemoryPassphraseReader::default();

        // Create infrastructure leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        let (actual_token_path, _) = sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        assert_eq!(token_path, actual_token_path);
    }

    #[test]
    fn if_correct_extension_is_not_present_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        let request_path = temp_path.join("token.ktr");
        let token_path = temp_path.join("token");

        let pass_reader = MemoryPassphraseReader::default();

        // Create infrastructure leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        let (actual_token_path, _) = sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        assert_eq!(
            token_path.with_extension(KEYSERVER_TOKEN_EXT),
            actual_token_path
        );
    }

    #[test]
    fn can_issue_keyserver_token_using_infrastructure_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create infrastructure leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let request_path = temp_path.join("token.ktr");
        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.kt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        assert!(token_path.exists());

        let result = load_token_bundle_from_file::<KeyserverTokenGroup>(&token_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn cannot_issue_keyserver_token_using_exemption_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Exemption>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let request_path = temp_path.join("token.ktr");
        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.kt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect_err("shouldn't be able to issue keyserver token with exemption cert");

        assert!(!token_path.exists());
    }

    #[test]
    fn cannot_issue_keyserver_token_using_manufacturer_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Manufacturer>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let request_path = temp_path.join("token.ktr");
        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.kt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect_err("shouldn't be able to issue keyserver token with manufacturer cert");

        assert!(!token_path.exists());
    }

    #[test]
    fn keyserver_token_created_via_cli_can_load_and_create_signature_with_associated_key() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let request_path = temp_path.join("token.ktr");
        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.kt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        // Load token and sign a message with its key
        let token_bundle = load_token_bundle_from_file::<KeyserverTokenGroup>(&token_path).unwrap();
        let token = token_bundle
            .token
            .load_key(token_kp)
            .expect("could not load token's key");
        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }

    #[test]
    fn keyserver_token_is_issued_with_cert_chain_which_validates() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, root_public_key) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = KeyserverTokenRequest::v1_token_request(
            token_kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let request_path = temp_path.join("token.ktr");
        save_token_request_to_file::<KeyserverTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.kt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        // Load token and validate its cert chain
        let token_bundle = load_token_bundle_from_file::<KeyserverTokenGroup>(&token_path).unwrap();

        let incorrect_root = KeyPair::new_random().public_key();

        token_bundle
            .validate_path_to_issuers(&[root_public_key], None)
            .expect("should find path to correct root");
        token_bundle
            .validate_path_to_issuers(&[incorrect_root], None)
            .expect_err("should not find path to incorrect root");
    }

    #[test]
    fn can_issue_database_token_using_infrastructure_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create infrastructure leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.dtr");
        save_token_request_to_file::<DatabaseTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.dt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Database,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        assert!(token_path.exists());

        let result = load_token_bundle_from_file::<DatabaseTokenGroup>(&token_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn cannot_issue_database_token_using_exemption_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Exemption>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.dtr");
        save_token_request_to_file::<DatabaseTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.dt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Keyserver,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect_err("shouldn't be able to issue database token with exemption cert");

        assert!(!token_path.exists());
    }

    #[test]
    fn cannot_issue_database_token_using_manufacturer_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Manufacturer>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());
        let request_path = temp_path.join("token.dtr");
        save_token_request_to_file::<DatabaseTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.dt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Database,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect_err("shouldn't be able to issue database token with manufacturer cert");

        assert!(!token_path.exists());
    }

    #[test]
    fn database_token_created_via_cli_can_load_and_create_signature_with_associated_key() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.dtr");
        save_token_request_to_file::<DatabaseTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.dt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Database,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        // Load token and sign a message with its key
        let token_bundle = load_token_bundle_from_file::<DatabaseTokenGroup>(&token_path).unwrap();
        let token = token_bundle
            .token
            .load_key(token_kp)
            .expect("could not load token's key");
        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }

    #[test]
    fn database_token_is_issued_with_cert_chain_which_validates() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, root_public_key) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.dtr");
        save_token_request_to_file::<DatabaseTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.dt");

        let opts = SignTokenOpts {
            token_type: TokenKind::Database,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        // Load token and validate its cert chain
        let token_bundle = load_token_bundle_from_file::<DatabaseTokenGroup>(&token_path).unwrap();

        let incorrect_root = KeyPair::new_random().public_key();

        token_bundle
            .validate_path_to_issuers(&[root_public_key], None)
            .expect("should find path to correct root");
        token_bundle
            .validate_path_to_issuers(&[incorrect_root], None)
            .expect_err("should not find path to incorrect root");
    }

    #[test]
    fn can_issue_hlt_token_using_infrastructure_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create infrastructure leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = HltTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.htr");
        save_token_request_to_file::<HltTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.ht");

        let opts = SignTokenOpts {
            token_type: TokenKind::Hlt,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        assert!(token_path.exists());

        let result = load_token_bundle_from_file::<HltTokenGroup>(&token_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn cannot_issue_hlt_token_using_exemption_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Exemption>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = HltTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.htr");
        save_token_request_to_file::<HltTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.ht");

        let opts = SignTokenOpts {
            token_type: TokenKind::Hlt,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect_err("shouldn't be able to issue HLT token with exemption cert");

        assert!(!token_path.exists());
    }

    #[test]
    fn cannot_issue_hlt_token_using_manufacturer_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Manufacturer>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = HltTokenRequest::v1_token_request(token_kp.public_key());
        let request_path = temp_path.join("token.htr");
        save_token_request_to_file::<HltTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.ht");

        let opts = SignTokenOpts {
            token_type: TokenKind::Hlt,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect_err("shouldn't be able to issue HLT token with manufacturer cert");

        assert!(!token_path.exists());
    }

    #[test]
    fn hlt_token_created_via_cli_can_load_and_create_signature_with_associated_key() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = HltTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.htr");
        save_token_request_to_file::<HltTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.ht");

        let opts = SignTokenOpts {
            token_type: TokenKind::Hlt,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        // Load token and sign a message with its key
        let token_bundle = load_token_bundle_from_file::<HltTokenGroup>(&token_path).unwrap();
        let token = token_bundle
            .token
            .load_key(token_kp)
            .expect("could not load token's key");
        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }

    #[test]
    fn hlt_token_is_issued_with_cert_chain_which_validates() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, root_public_key) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = HltTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.htr");
        save_token_request_to_file::<HltTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.ht");

        let opts = SignTokenOpts {
            token_type: TokenKind::Hlt,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        // Load token and validate its cert chain
        let token_bundle = load_token_bundle_from_file::<HltTokenGroup>(&token_path).unwrap();

        let incorrect_root = KeyPair::new_random().public_key();

        token_bundle
            .validate_path_to_issuers(&[root_public_key], None)
            .expect("should find path to correct root");
        token_bundle
            .validate_path_to_issuers(&[incorrect_root], None)
            .expect_err("should not find path to incorrect root");
    }

    #[test]
    fn can_issue_synthesizer_token_using_manufacturer_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create infrastructure leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Manufacturer>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;
        let token_kp = KeyPair::new_random();
        let request = SynthesizerTokenRequest::v1_token_request(
            token_kp.public_key(),
            domain,
            model,
            serial,
            max_dna_base_pairs_per_day,
            None,
        );

        let request_path = temp_path.join("token.str");
        save_token_request_to_file::<SynthesizerTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.st");

        let opts = SignTokenOpts {
            token_type: TokenKind::Synthesizer,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        assert!(token_path.exists());

        let result = load_token_bundle_from_file::<SynthesizerTokenGroup>(&token_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn cannot_issue_synthesizer_token_using_exemption_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Exemption>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;
        let token_kp = KeyPair::new_random();
        let request = SynthesizerTokenRequest::v1_token_request(
            token_kp.public_key(),
            domain,
            model,
            serial,
            max_dna_base_pairs_per_day,
            None,
        );

        let request_path = temp_path.join("token.str");
        save_token_request_to_file::<SynthesizerTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.st");

        let opts = SignTokenOpts {
            token_type: TokenKind::Synthesizer,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect_err("shouldn't be able to issue synthesizer token with exemption cert");

        assert!(!token_path.exists());
    }

    #[test]
    fn cannot_issue_synthesizer_token_using_infrastructure_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;
        let token_kp = KeyPair::new_random();
        let request = SynthesizerTokenRequest::v1_token_request(
            token_kp.public_key(),
            domain,
            model,
            serial,
            max_dna_base_pairs_per_day,
            None,
        );

        let request_path = temp_path.join("token.str");
        save_token_request_to_file::<SynthesizerTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.st");

        let opts = SignTokenOpts {
            token_type: TokenKind::Synthesizer,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect_err("shouldn't be able to issue synthesizer token with infrastructure cert");

        assert!(!token_path.exists());
    }

    #[test]
    fn synthesizer_token_created_via_cli_can_load_and_create_signature_with_associated_key() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Manufacturer>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;
        let token_kp = KeyPair::new_random();
        let request = SynthesizerTokenRequest::v1_token_request(
            token_kp.public_key(),
            domain,
            model,
            serial,
            max_dna_base_pairs_per_day,
            None,
        );

        let request_path = temp_path.join("token.str");
        save_token_request_to_file::<SynthesizerTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.st");

        let opts = SignTokenOpts {
            token_type: TokenKind::Synthesizer,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };

        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        // Load token and sign a message with its key
        let token_bundle =
            load_token_bundle_from_file::<SynthesizerTokenGroup>(&token_path).unwrap();
        let token = token_bundle
            .token
            .load_key(token_kp)
            .expect("could not load token's key");
        let signature = token.sign(b"message");
        assert!(token.verify(b"message", &signature).is_ok());
    }

    #[test]
    fn synthesizer_token_is_issued_with_cert_chain_which_validates() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, root_public_key) = create_leaf_bundle::<Manufacturer>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;
        let token_kp = KeyPair::new_random();
        let request = SynthesizerTokenRequest::v1_token_request(
            token_kp.public_key(),
            domain,
            model,
            serial,
            max_dna_base_pairs_per_day,
            None,
        );

        let request_path = temp_path.join("token.str");
        save_token_request_to_file::<SynthesizerTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.st");

        let opts = SignTokenOpts {
            token_type: TokenKind::Synthesizer,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path.clone()),
        };
        sign_token::run(&opts, pass_reader, &default_dir).unwrap();

        // Load token and validate its cert chain
        let token_bundle =
            load_token_bundle_from_file::<SynthesizerTokenGroup>(&token_path).unwrap();

        let incorrect_root = KeyPair::new_random().public_key();

        token_bundle
            .validate_path_to_issuers(&[root_public_key], None)
            .expect("should find path to correct root");
        token_bundle
            .validate_path_to_issuers(&[incorrect_root], None)
            .expect_err("should not find path to incorrect root");
    }

    #[test]
    fn can_infer_certificate_extension_when_signing() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path.with_extension(CERT_EXT)).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = HltTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.htr");
        save_token_request_to_file::<HltTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.ht");

        let opts = SignTokenOpts {
            token_type: TokenKind::Hlt,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect("should have been able to infer certificate extension");
    }

    #[test]
    fn can_infer_token_request_extension_when_signing() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key.priv");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(cert_kp, &pass_reader.passphrase, &cert_key_path).unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = HltTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token");
        save_token_request_to_file::<HltTokenGroup>(
            request,
            &request_path.with_extension(HltTokenGroup::REQUEST_EXT),
        )
        .unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.ht");

        let opts = SignTokenOpts {
            token_type: TokenKind::Hlt,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect("should have been able to infer token request extension");
    }

    #[test]
    fn can_infer_key_extension_when_signing() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");

        let pass_reader = MemoryPassphraseReader::default();

        // Create leaf cert and save to file
        let (cert_bundle, cert_kp, _) = create_leaf_bundle::<Infrastructure>();

        let cert_path = temp_path.join("leaf.cert");
        let cert_key_path = temp_path.join("leaf_key");
        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();
        save_keypair_to_file(
            cert_kp,
            &pass_reader.passphrase,
            &cert_key_path.with_extension(KEY_PRIV_EXT),
        )
        .unwrap();

        // Create token request and save to file
        let token_kp = KeyPair::new_random();
        let request = HltTokenRequest::v1_token_request(token_kp.public_key());

        let request_path = temp_path.join("token.htr");
        save_token_request_to_file::<HltTokenGroup>(request, &request_path).unwrap();

        // Issue token from token request using cert
        let token_path = temp_path.join("token.ht");

        let opts = SignTokenOpts {
            token_type: TokenKind::Hlt,
            token_request: request_path,
            cert: cert_path,
            key: Some(cert_key_path),
            days_valid: None,
            output: Some(token_path),
        };

        sign_token::run(&opts, pass_reader, &default_dir)
            .expect("should have been able to infer key extension");
    }
}
