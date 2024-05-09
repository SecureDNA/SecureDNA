// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for using a certificate to sign another certificate, or self-signing a root certificate request

use std::path::Path;
use std::{io::Write, path::PathBuf};

use crate::default_filename::set_appropriate_filepath_and_create_default_dir_if_required;
use crate::passphrase_reader::{PassphraseReader, PassphraseSource, ENV_PASSPHRASE_WARNING};
use certificates::file::CERT_REQUEST_EXT;
use certificates::{
    file::{
        load_cert_request_from_file, load_certificate_bundle_from_file, load_keypair_from_file,
        save_certificate_bundle_to_file, CERT_EXT, KEY_PRIV_EXT,
    },
    CertificateBundle, Exemption, HierarchyKind, Infrastructure, IssuerAdditionalFields,
    Manufacturer, Role, RoleKind,
};
use clap::{crate_version, Parser, Subcommand};

use super::error::CertCliError;

#[derive(Debug, Parser)]
#[clap(
    name = "sdna-sign-cert",
    about = "Signs a SecureDNA certificate request",
    version = crate_version!()
)]
pub struct SignCertOpts {
    #[clap(
        help = "Role of certificate(s) [possible values: exemption, infrastructure, manufacturer]"
    )]
    pub role: RoleKind,
    #[clap(
        global = true,
        long,
        help = "Filepath where issuer's private key can be found (optional). If this is not provided, an attempt will be made to infer it by using the filepath of the certificate"
    )]
    pub key: Option<PathBuf>,
    #[clap(
        global = true,
        long,
        help = "How many days after today the certificate will be valid for (optional, default is 28)"
    )]
    pub days_valid: Option<i64>,
    #[clap(
        global = true,
        long,
        help = "Email(s) to be notified when an ELT issued by this cert is used (optional, only for exemption leaf certs)"
    )]
    pub notify: Vec<String>,
    #[clap(
        global = true,
        long,
        help = "Filepath where new certificate will be saved (optional). If this is not provided it will be derived from the request filepath"
    )]
    pub output: Option<PathBuf>,
    #[clap(subcommand)]
    pub sign_type: SignType,
}

#[derive(Debug, Subcommand)]
pub enum SignType {
    /// Use a certificate to sign a certificate request
    Sign {
        #[clap(help = "Filepath where certificate request can be found")]
        request: PathBuf,
        #[clap(help = "Filepath where issuing certificate can be found")]
        cert: PathBuf,
    },
    /// Self sign a root certificate request
    SelfSign {
        #[clap(help = "Filepath where certificate request can be found")]
        request: PathBuf,
    },
}

pub fn main<P: PassphraseReader, W: Write, E: Write>(
    opts: &SignCertOpts,
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
                "A newly issued certificate has been saved to {}",
                filepath.display()
            )
        }
        Err(err) => writeln!(stderr, "{err}"),
    }
}

fn run<P: PassphraseReader>(
    opts: &SignCertOpts,
    passphrase_reader: P,
    default_directory: &Path,
) -> Result<(PathBuf, PassphraseSource), CertCliError> {
    match opts.role {
        RoleKind::Exemption => {
            sign_cert::<Exemption, _>(opts, passphrase_reader, default_directory)
        }
        RoleKind::Infrastructure => {
            sign_cert::<Infrastructure, _>(opts, passphrase_reader, default_directory)
        }
        RoleKind::Manufacturer => {
            sign_cert::<Manufacturer, _>(opts, passphrase_reader, default_directory)
        }
    }
}

fn sign_cert<R: Role, P: PassphraseReader>(
    opts: &SignCertOpts,
    passphrase_reader: P,
    default_directory: &Path,
) -> Result<(PathBuf, PassphraseSource), CertCliError> {
    let mut issuer_fields = IssuerAdditionalFields::default().with_emails_to_notify(&opts.notify);
    if let Some(days_valid) = opts.days_valid {
        issuer_fields = issuer_fields.with_expiry_in_days(days_valid)?;
    };

    let key_path = match &opts.key {
        // If key path has been provided add extension if not present
        Some(path) => match path.extension() {
            Some(_) => path.to_owned(),
            None => path.with_extension(KEY_PRIV_EXT),
        },
        None => {
            match &opts.sign_type {
                // If not provided we can try to infer from corresponding certificate/request
                SignType::Sign { request: _, cert } => cert.with_extension(KEY_PRIV_EXT),
                SignType::SelfSign { request } => request.with_extension(KEY_PRIV_EXT),
            }
        }
    };

    let (new_cert_bundle, passphrase_source) = match &opts.sign_type {
        SignType::Sign { request, cert } => {
            let cert = match cert.extension() {
                Some(_) => cert.to_owned(),
                None => cert.with_extension(CERT_EXT),
            };
            let issuing_cb = load_certificate_bundle_from_file::<R>(&cert)?;

            let (passphrase, source) = passphrase_reader
                .read_passphrase()
                .map_err(CertCliError::from)?;

            let keypair = load_keypair_from_file(&key_path, passphrase)?;

            let issuing_cert = issuing_cb
                .get_lead_cert()
                .map_err(|_| CertCliError::NoSuitableCertificate)?
                .to_owned()
                .load_key(keypair)?;

            let request_file = match request.extension() {
                Some(_) => request.to_owned(),
                None => request.with_extension(CERT_REQUEST_EXT),
            };
            let request = load_cert_request_from_file::<R>(&request_file)?;

            if !opts.notify.is_empty()
                && (opts.role != RoleKind::Exemption
                    || request.hierarchy_level() != HierarchyKind::Leaf)
            {
                return Err(CertCliError::EmailsToNotifyNotAllowed);
            }

            let new_cert = issuing_cert.issue_cert(request, issuer_fields)?;

            // Root certs don't need to provide a certificate chain for the certificates they issue, because the root public keys will be known.
            let chain = match issuing_cert.hierarchy_level() {
                HierarchyKind::Root => None,
                _ => Some(issuing_cb.issue_chain()),
            };
            Ok::<_, CertCliError>((CertificateBundle::new(new_cert, chain), source))
        }
        SignType::SelfSign { request } => {
            let request_file = match request.extension() {
                Some(_) => request.to_owned(),
                None => request.with_extension(CERT_REQUEST_EXT),
            };
            let request = load_cert_request_from_file::<R>(&request_file)?;

            let (passphrase, source) = passphrase_reader
                .read_passphrase()
                .map_err(CertCliError::from)?;

            let keypair = load_keypair_from_file(&key_path, passphrase)?;

            let request = request.load_key(keypair)?;

            let new_cert = request.self_sign(issuer_fields)?;
            Ok((CertificateBundle::new(new_cert, None), source))
        }
    }?;

    // If no path is provided for certificate destination we will derive it from the request filepath.
    let cert_path = set_appropriate_filepath_and_create_default_dir_if_required(
        opts.output.as_ref(),
        CERT_EXT,
        || {
            let request = match &opts.sign_type {
                SignType::Sign { request, cert: _ } => request,
                SignType::SelfSign { request } => request,
            };
            request.with_extension(CERT_EXT)
        },
        default_directory,
    )?;

    save_certificate_bundle_to_file(new_cert_bundle, &cert_path)?;

    Ok((cert_path, passphrase_source))
}

#[cfg(test)]
mod tests {

    use certificates::{
        file::{save_cert_request_to_file, save_keypair_to_file, FileError},
        Builder, ChainTraversal, KeyPair, RequestBuilder,
    };
    use tempfile::TempDir;

    use crate::passphrase_reader::{
        EnvVarPassphraseReader, MemoryPassphraseReader, PassphraseReaderError,
        KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
    };
    use crate::shims::sign_cert;

    use super::*;
    #[test]
    fn nonexistent_request_file_handled_gracefully() {
        let default_dir = TempDir::new().unwrap();
        let request = PathBuf::from("non/existent.certr");
        let key = PathBuf::from("non/existent.priv");

        let opts = SignCertOpts {
            key: Some(key),
            days_valid: None,
            output: None,
            sign_type: SignType::SelfSign { request },
            role: RoleKind::Exemption,
            notify: vec![],
        };
        let passphrase_reader = MemoryPassphraseReader::default();
        let result = run(&opts, passphrase_reader, default_dir.path())
            .expect_err("CLI should error on non-existent request file");
        assert!(matches!(
            result,
            CertCliError::FileError(FileError::CouldNotReadFromFile(..))
        ));
    }

    #[test]
    fn can_self_sign_root_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let cert_path = temp_path.join("root.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect("CLI should be able to self sign root cert");

        assert!(cert_path.exists());
        let result = load_certificate_bundle_from_file::<Infrastructure>(&cert_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn default_dir_is_created_if_not_present_and_required_for_output() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let cert_path = default_dir.join("root.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir).unwrap();

        assert!(default_dir.exists())
    }

    #[test]
    fn default_dir_is_not_created_if_not_required() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let cert_path = temp_path.join("root.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir).unwrap();

        assert!(!default_dir.exists())
    }

    #[test]
    fn if_correct_extension_is_present_no_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let cert_path = temp_path.join("root.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        let (actual_cert_path, _) = sign_cert::run(&opts, passphrase_reader, &default_dir).unwrap();

        assert_eq!(cert_path, actual_cert_path);
    }

    #[test]
    fn if_correct_extension_is_not_present_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let cert_path = temp_path.join("root");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        let (actual_cert_path, _) = sign_cert::run(&opts, passphrase_reader, &default_dir).unwrap();

        assert_eq!(cert_path.with_extension(CERT_EXT), actual_cert_path);
    }

    #[test]
    fn sign_cert_can_infer_key_path_from_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let cert_path = temp_path.join("root.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            // No key path provided
            key: None,
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir).unwrap();

        assert!(cert_path.exists());

        let result = load_certificate_bundle_from_file::<Infrastructure>(&cert_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn sign_cert_can_infer_cert_path_from_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let expected_cert_path = request_path.with_extension("cert");
        let key_path = temp_path.join("root.priv");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            // No cert path provided
            output: None,
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir).unwrap();

        assert!(expected_cert_path.exists());

        let result = load_certificate_bundle_from_file::<Infrastructure>(&expected_cert_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn cannot_self_sign_root_cert_with_mismatched_key() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let cert_path = temp_path.join("root.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(
            KeyPair::new_random(),
            &passphrase_reader.passphrase,
            &key_path,
        )
        .unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        let error = sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect_err("should not be able to self sign with incorrect key");

        assert!(!cert_path.exists());
        assert_eq!(error, CertCliError::KeyMismatch);
    }

    #[test]
    fn cannot_sign_if_key_passphrase_entered_incorrectly() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let cert_path = temp_path.join("root.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, passphrase_reader.wrong_passphrase(), &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        let error = sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect_err("should not be able to sign if incorrect passphrase entered");

        assert!(!cert_path.exists());

        assert_eq!(error, CertCliError::KeyDecrypt);
    }

    #[test]
    fn cannot_self_sign_intermediate_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("int.certr");
        let key_path = temp_path.join("int.priv");
        let cert_path = temp_path.join("int.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req =
            RequestBuilder::<Infrastructure>::intermediate_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        let error = sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect_err("intermediate should not be able to self sign");

        assert!(!cert_path.exists());

        let expected_error = CertCliError::IssuanceError(
            certificates::IssuanceError::NotAbleToSelfSign(HierarchyKind::Intermediate.to_string()),
        );
        assert_eq!(error, expected_error);
    }

    #[test]
    fn cannot_self_sign_leaf_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("leaf.certr");
        let key_path = temp_path.join("leaf.priv");
        let cert_path = temp_path.join("leaf.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Manufacturer>::leaf_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Manufacturer,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path.clone()),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        let error = sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect_err("leaef cert should not be able to self sign");

        assert!(!cert_path.exists());

        let expected_error = CertCliError::IssuanceError(
            certificates::IssuanceError::NotAbleToSelfSign(HierarchyKind::Leaf.to_string()),
        );

        assert_eq!(error, expected_error);
    }

    #[test]
    fn root_cert_can_sign_intermediate_req() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let root_cert_path = temp_path.join("root.cert");
        let root_key_path = temp_path.join("root.priv");
        let int_req_path = temp_path.join("int.certr");
        let int_cert_path = temp_path.join("int.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let root_kp = KeyPair::new_random();
        save_keypair_to_file(root_kp, &passphrase_reader.passphrase, &root_key_path).unwrap();
        let root_kp =
            load_keypair_from_file(&root_key_path, &passphrase_reader.passphrase).unwrap();

        let root_cert = RequestBuilder::<Manufacturer>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let root_cert_bundle = CertificateBundle::new(root_cert, None);
        save_certificate_bundle_to_file(root_cert_bundle, &root_cert_path).unwrap();

        let int_req = RequestBuilder::<Manufacturer>::intermediate_v1_builder(
            KeyPair::new_random().public_key(),
        )
        .build();

        save_cert_request_to_file(int_req, &int_req_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Manufacturer,
            key: Some(root_key_path),
            days_valid: None,
            output: Some(int_cert_path.clone()),
            sign_type: SignType::Sign {
                request: int_req_path,
                cert: root_cert_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect("root cert should be able to sign intermediate");

        assert!(int_cert_path.exists());
        let result = load_certificate_bundle_from_file::<Manufacturer>(&int_cert_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn root_cert_cannot_sign_intermediate_req_with_different_role() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let root_cert_path = temp_path.join("root.cert");
        let root_key_path = temp_path.join("root.priv");
        let int_req_path = temp_path.join("int.certr");
        let int_cert_path = temp_path.join("int.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let root_kp = KeyPair::new_random();
        save_keypair_to_file(root_kp, &passphrase_reader.passphrase, &root_key_path).unwrap();
        let root_kp =
            load_keypair_from_file(&root_key_path, &passphrase_reader.passphrase).unwrap();

        let root_cert = RequestBuilder::<Infrastructure>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let root_cert_bundle = CertificateBundle::new(root_cert, None);
        save_certificate_bundle_to_file(root_cert_bundle, &root_cert_path).unwrap();

        let int_req = RequestBuilder::<Exemption>::intermediate_v1_builder(
            KeyPair::new_random().public_key(),
        )
        .build();

        save_cert_request_to_file(int_req, &int_req_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(root_key_path),
            days_valid: None,
            output: Some(int_cert_path.clone()),
            sign_type: SignType::Sign {
                request: int_req_path.clone(),
                cert: root_cert_path,
            },
            notify: vec![],
        };

        let error = sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect_err("should not be able to issue cert with different role");

        assert!(!int_cert_path.exists());

        let expected_error = CertCliError::FileError(FileError::UnexpectedCertFileContents(
            int_req_path,
            "certificate request".to_string(),
        ));
        assert_eq!(error, expected_error);
    }

    #[test]
    fn intermediate_cert_can_sign_leaf_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let int_cert_path = temp_path.join("int.cert");
        let int_key_path = temp_path.join("int.priv");
        let leaf_req_path = temp_path.join("leaf.certr");
        let leaf_cert_path = temp_path.join("leaf.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let root_kp = KeyPair::new_random();
        let root_public_key = root_kp.public_key();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(root_public_key)
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();

        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();
        save_keypair_to_file(int_kp, &passphrase_reader.passphrase, &int_key_path).unwrap();

        let int_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .unwrap();
        let int_bundle = CertificateBundle::new(int_cert, None);
        save_certificate_bundle_to_file(int_bundle, &int_cert_path).unwrap();
        let leaf_req =
            RequestBuilder::<Exemption>::leaf_v1_builder(KeyPair::new_random().public_key())
                .build();
        save_cert_request_to_file(leaf_req, &leaf_req_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Exemption,
            key: Some(int_key_path),
            days_valid: None,
            output: Some(leaf_cert_path.clone()),
            sign_type: SignType::Sign {
                request: leaf_req_path,
                cert: int_cert_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect("intermediate cert should be able to sign leaf");

        assert!(leaf_cert_path.exists());
        let leaf_cert = load_certificate_bundle_from_file::<Exemption>(&leaf_cert_path).unwrap();
        leaf_cert
            .validate_path_to_issuers(&[root_public_key], None)
            .expect("should find path to root")
    }

    #[test]
    fn intermediate_cert_can_sign_intermediate_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let int_cert_path = temp_path.join("int.cert");
        let int_key_path = temp_path.join("int.priv");
        let int2_req_path = temp_path.join("int2.certr");
        let int2_cert_path = temp_path.join("int2.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let root_kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Infrastructure>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();

        let int_req =
            RequestBuilder::<Infrastructure>::intermediate_v1_builder(int_kp.public_key()).build();
        save_keypair_to_file(int_kp, &passphrase_reader.passphrase, &int_key_path).unwrap();

        let int_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .unwrap();
        let int_bundle = CertificateBundle::new(int_cert, None);
        save_certificate_bundle_to_file(int_bundle, &int_cert_path).unwrap();
        let int2_req = RequestBuilder::<Infrastructure>::intermediate_v1_builder(
            KeyPair::new_random().public_key(),
        )
        .build();
        save_cert_request_to_file(int2_req, &int2_req_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(int_key_path),
            days_valid: None,
            output: Some(int2_cert_path.clone()),
            sign_type: SignType::Sign {
                request: int2_req_path,
                cert: int_cert_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect("intermediate should be able to sign intermediate");

        assert!(int2_cert_path.exists());
        let result = load_certificate_bundle_from_file::<Infrastructure>(&int2_cert_path);
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn warning_printed_to_stderr_on_signing_cert_request_using_env_passphrase_reader() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let cert_path = temp_path.join("root.cert");
        let request_path = temp_path.join("int.certr");
        let int_cert_path = temp_path.join("int.cert");
        let key_path = temp_path.join("1234.priv");

        let test_passphrase = "12345678";

        let kp = KeyPair::new_random();

        save_keypair_to_file(kp.clone(), test_passphrase, &key_path).unwrap();

        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let cert_bundle = CertificateBundle::new(root_cert, None);

        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        save_cert_request_to_file(int_req, &request_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Exemption,
            key: Some(key_path),
            days_valid: None,
            output: Some(int_cert_path.clone()),
            sign_type: SignType::Sign {
                request: request_path,
                cert: cert_path,
            },
            notify: vec![],
        };

        let passphrase_reader = EnvVarPassphraseReader;

        let mut stdout = vec![];
        let mut stderr = vec![];

        temp_env::with_var(
            KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
            Some(test_passphrase),
            || {
                sign_cert::main(
                    &opts,
                    passphrase_reader,
                    &default_dir,
                    &mut stdout,
                    &mut stderr,
                )
            },
        )
        .unwrap();

        assert!(int_cert_path.exists());

        let output = String::from_utf8_lossy(&stderr);
        assert!(output.contains(ENV_PASSPHRASE_WARNING.trim()));
    }

    #[test]
    fn sign_cert_request_using_env_passphrase_reader_fails_gracefully_if_env_variable_not_present()
    {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let cert_path = temp_path.join("root.cert");
        let request_path = temp_path.join("int.certr");
        let int_cert_path = temp_path.join("int.cert");
        let key_path = temp_path.join("1234.priv");

        let test_passphrase = "12345678";

        let kp = KeyPair::new_random();

        save_keypair_to_file(kp.clone(), test_passphrase, &key_path).unwrap();

        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let cert_bundle = CertificateBundle::new(root_cert, None);

        save_certificate_bundle_to_file(cert_bundle, &cert_path).unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        save_cert_request_to_file(int_req, &request_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Exemption,
            key: Some(key_path),
            days_valid: None,
            output: Some(int_cert_path.clone()),
            sign_type: SignType::Sign {
                request: request_path,
                cert: cert_path,
            },
            notify: vec![],
        };

        let passphrase_reader = EnvVarPassphraseReader;

        let err = temp_env::with_var_unset(KEY_ENCRYPTION_PASSPHRASE_ENV_VAR, || {
            sign_cert::run(&opts, passphrase_reader, &default_dir)
        })
        .expect_err(
            "sign cert should not succeed when using env passphrase reader with env var unset",
        );

        assert!(!int_cert_path.exists());
        assert_eq!(
            err,
            CertCliError::CouldNotReadPassphrase(PassphraseReaderError::EnvVariableNotFound)
        )
    }

    #[test]
    fn can_infer_request_extension_when_self_signing() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("root");
        let key_path = temp_path.join("root.priv");
        let cert_path = temp_path.join("root.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path.with_extension(CERT_REQUEST_EXT)).unwrap();
        save_keypair_to_file(kp, &passphrase_reader.passphrase, &key_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Infrastructure,
            key: Some(key_path),
            days_valid: None,
            output: Some(cert_path),
            sign_type: SignType::SelfSign {
                request: request_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect("should infer request extension");
    }

    #[test]
    fn can_infer_request_extension_when_signing() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let root_cert_path = temp_path.join("root.cert");
        let root_key_path = temp_path.join("root.priv");
        let int_req_path = temp_path.join("int");
        let int_cert_path = temp_path.join("int.cert");

        let passphrase_reader = MemoryPassphraseReader::default();

        let root_kp = KeyPair::new_random();
        save_keypair_to_file(root_kp, &passphrase_reader.passphrase, &root_key_path).unwrap();
        let root_kp =
            load_keypair_from_file(&root_key_path, &passphrase_reader.passphrase).unwrap();

        let root_cert = RequestBuilder::<Manufacturer>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let root_cert_bundle = CertificateBundle::new(root_cert, None);
        save_certificate_bundle_to_file(root_cert_bundle, &root_cert_path).unwrap();

        let int_req = RequestBuilder::<Manufacturer>::intermediate_v1_builder(
            KeyPair::new_random().public_key(),
        )
        .build();

        save_cert_request_to_file(int_req, &int_req_path.with_extension(CERT_REQUEST_EXT)).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Manufacturer,
            key: Some(root_key_path),
            days_valid: None,
            output: Some(int_cert_path),
            sign_type: SignType::Sign {
                request: int_req_path,
                cert: root_cert_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect("should have been able to infer request extension");
    }

    #[test]
    fn can_infer_certificate_extension_when_signing() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let root_cert_path = temp_path.join("root.cert");
        let root_key_path = temp_path.join("root.priv");
        let int_req_path = temp_path.join("int.certr");
        let int_cert_path = temp_path.join("int");

        let passphrase_reader = MemoryPassphraseReader::default();

        let root_kp = KeyPair::new_random();
        save_keypair_to_file(root_kp, &passphrase_reader.passphrase, &root_key_path).unwrap();
        let root_kp =
            load_keypair_from_file(&root_key_path, &passphrase_reader.passphrase).unwrap();

        let root_cert = RequestBuilder::<Manufacturer>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let root_cert_bundle = CertificateBundle::new(root_cert, None);
        save_certificate_bundle_to_file(root_cert_bundle, &root_cert_path).unwrap();

        let int_req = RequestBuilder::<Manufacturer>::intermediate_v1_builder(
            KeyPair::new_random().public_key(),
        )
        .build();

        save_cert_request_to_file(int_req, &int_req_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Manufacturer,
            key: Some(root_key_path),
            days_valid: None,
            output: Some(int_cert_path),
            sign_type: SignType::Sign {
                request: int_req_path,
                cert: root_cert_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect("should have been able to infer request extension");
    }

    #[test]
    fn can_infer_key_extension_when_signing() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let root_cert_path = temp_path.join("root.cert");
        let root_key_path = temp_path.join("root");
        let int_req_path = temp_path.join("int.certr");
        let int_cert_path = temp_path.join("int");

        let passphrase_reader = MemoryPassphraseReader::default();

        let root_kp = KeyPair::new_random();

        let root_cert = RequestBuilder::<Manufacturer>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let root_cert_bundle = CertificateBundle::new(root_cert, None);
        save_certificate_bundle_to_file(root_cert_bundle, &root_cert_path).unwrap();
        save_keypair_to_file(
            root_kp,
            &passphrase_reader.passphrase,
            &root_key_path.with_extension(KEY_PRIV_EXT),
        )
        .unwrap();

        let int_req = RequestBuilder::<Manufacturer>::intermediate_v1_builder(
            KeyPair::new_random().public_key(),
        )
        .build();

        save_cert_request_to_file(int_req, &int_req_path).unwrap();

        let opts = SignCertOpts {
            role: RoleKind::Manufacturer,
            key: Some(root_key_path),
            days_valid: None,
            output: Some(int_cert_path),
            sign_type: SignType::Sign {
                request: int_req_path,
                cert: root_cert_path,
            },
            notify: vec![],
        };

        sign_cert::run(&opts, passphrase_reader, &default_dir)
            .expect("should have been able to infer key extension");
    }
}
