// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use clap::{crate_version, Parser};

use super::error::CertCliError;
use crate::default_filepath::set_appropriate_filepath_and_create_default_dir_if_required;
use crate::{
    default_filepath::get_default_filename_for_cert_request,
    key::{AssociatedKey, AssociatedKeyArgs, KeySource, NewKeyDetails},
    passphrase_reader::{PassphraseReader, PassphraseSource, ENV_PASSPHRASE_WARNING},
};
use certificates::file::CERT_REQUEST_EXT;
use certificates::{
    file::save_cert_request_to_file, Builder, CertificateRequest, Description, Exemption,
    HierarchyKind, Infrastructure, KeyUnavailable, Manufacturer, RequestBuilder, Role, RoleKind,
};

#[derive(Debug, Parser)]
#[clap(
name = "sdna-create-cert",
about = "Generates a SecureDNA certificate request",
version = crate_version!()
)]

pub struct CreateCertOpts {
    #[clap(
        help = "Role of certificate [possible values: exemption, infrastructure, manufacturer]"
    )]
    pub role: RoleKind,
    #[clap(help = "Hierarchy level of certificate [possible values: root, intermediate, leaf]")]
    pub hierarchy: HierarchyKind,
    #[clap(flatten)]
    pub key: AssociatedKeyArgs,
    #[clap(long, help = "Name of certificate creator (optional)")]
    pub name: Option<String>,
    #[clap(long, help = "Email of certificate creator (optional)")]
    pub email: Option<String>,
    #[clap(
        long,
        help = "Email(s) to be notified when an exemption token issued by this cert is used (optional, only for exemption leaf certs)"
    )]
    pub notify: Vec<String>,
    #[clap(
        long,
        action,
        help = "Determines whether the certificate is able to issue blinded certificates or tokens (optional, only for exemption certs)"
    )]
    pub allow_blinding: bool,
    #[clap(
        long,
        help = "Filepath where the certificate request will be saved (optional). If this is not provided ~/SecureDNA will be used"
    )]
    pub output: Option<PathBuf>,
}

pub fn main<P, W, E>(
    opts: &CreateCertOpts,
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
                "Saved new certificate request to {}",
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

type BuilderFn<R> = fn(RequestBuilder<R>) -> RequestBuilder<R>;

fn run<P: PassphraseReader>(
    opts: &CreateCertOpts,
    passphrase_reader: &P,
    default_directory: &Path,
) -> Result<(PathBuf, KeySource), CertCliError> {
    if !opts.notify.is_empty()
        && (opts.role != RoleKind::Exemption || opts.hierarchy != HierarchyKind::Leaf)
    {
        return Err(CertCliError::EmailsToNotifyNotAllowed);
    }
    if opts.allow_blinding && opts.role != RoleKind::Exemption {
        return Err(CertCliError::AllowBlindingNotAllowed);
    }

    match opts.role {
        RoleKind::Exemption => {
            let role_specific_opts = |builder: RequestBuilder<Exemption>| {
                let builder = if !opts.notify.is_empty() {
                    builder.with_emails_to_notify(&opts.notify)
                } else {
                    builder
                };
                if opts.allow_blinding {
                    builder.allow_blinding(true)
                } else {
                    builder
                }
            };
            create_cert_request::<_, Exemption, _>(
                opts,
                passphrase_reader,
                default_directory,
                Some(role_specific_opts),
            )
        }
        RoleKind::Infrastructure => create_cert_request::<_, Infrastructure, BuilderFn<_>>(
            opts,
            passphrase_reader,
            default_directory,
            None,
        ),
        RoleKind::Manufacturer => create_cert_request::<_, Manufacturer, BuilderFn<_>>(
            opts,
            passphrase_reader,
            default_directory,
            None,
        ),
    }
}

fn create_cert_request<P: PassphraseReader, R: Role, F>(
    opts: &CreateCertOpts,
    passphrase_reader: &P,
    default_directory: &Path,
    role_specific_builder_opts_fn: Option<F>,
) -> Result<(PathBuf, KeySource), CertCliError>
where
    RequestBuilder<R>: Builder<Item = CertificateRequest<R, KeyUnavailable>>,
    F: Fn(RequestBuilder<R>) -> RequestBuilder<R>,
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

    let builder = match opts.hierarchy {
        HierarchyKind::Root => RequestBuilder::<R>::root_v1_builder(public_key),
        HierarchyKind::Intermediate => RequestBuilder::<R>::intermediate_v1_builder(public_key),
        HierarchyKind::Leaf => RequestBuilder::<R>::leaf_v1_builder(public_key),
    };

    let mut desc = Description::default();
    if let Some(name) = &opts.name {
        desc = desc.with_name(name);
    }
    if let Some(email) = &opts.email {
        desc = desc.with_email(email);
    }

    let mut builder = builder.with_description(desc);

    if let Some(extra_fn) = role_specific_builder_opts_fn {
        builder = extra_fn(builder);
    }

    let req = builder.build();

    // If the request destination has not been provided then we will use the default directory and a default filename.
    let request_path: PathBuf = set_appropriate_filepath_and_create_default_dir_if_required(
        opts.output.as_ref(),
        CERT_REQUEST_EXT,
        || default_directory.join(get_default_filename_for_cert_request(&req)),
        default_directory,
    )?;

    save_cert_request_to_file(req, &request_path)?;

    Ok((request_path, key_source))
}

#[cfg(test)]
mod tests {
    use crate::inspect::{FormatMethod, Formattable, SingleRequestOutput};
    use crate::key::{AssociatedKeyArgs, KeySource, NewKeyDetails};
    use crate::shims::create_cert::{self, CreateCertOpts};
    use crate::shims::error::CertCliError;

    use crate::passphrase_reader::{
        EnvVarPassphraseReader, MemoryPassphraseReader, PassphraseReaderError, PassphraseSource,
        ENV_PASSPHRASE_WARNING, KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
    };
    use certificates::file::{
        load_cert_request_from_file, load_keypair_from_file, save_public_key_to_file,
        CERT_REQUEST_EXT, KEY_PRIV_EXT, KEY_PUB_EXT,
    };
    use certificates::{
        Exemption, HierarchyKind, Infrastructure, KeyPair, Manufacturer, RequestDigest, RoleKind,
    };
    use tempfile::TempDir;

    #[test]
    fn can_create_root_manufacturer_cert_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
            notify: vec![],
            allow_blinding: false,
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect("could not create root manufacturer certificate request");

        assert!(request_path.exists());
        assert!(key_path.exists());

        let result = load_cert_request_from_file::<Manufacturer>(&request_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn can_create_intermediate_infrastructure_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("int.certr");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Intermediate,
            role: RoleKind::Infrastructure,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: false,
            key: AssociatedKeyArgs::default(),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect("could not create intermediate infrastructure certificate request");

        assert!(request_path.exists());

        let result = load_cert_request_from_file::<Infrastructure>(&request_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn can_create_leaf_exemption_certificate_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("leaf.certr");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Leaf,
            role: RoleKind::Exemption,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: false,
            key: AssociatedKeyArgs::default(),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect("could not create leaf exemption certificate request");

        assert!(request_path.exists());

        let result = load_cert_request_from_file::<Exemption>(&request_path);
        assert!(result.is_ok(), "{:?}", result.err())
    }

    #[test]
    fn request_and_key_saved_to_default_directory_when_no_destination_provided() {
        let default_directory = TempDir::new().unwrap();

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Leaf,
            role: RoleKind::Infrastructure,
            name: None,
            email: None,
            output: None,
            notify: vec![],
            allow_blinding: false,
            key: AssociatedKeyArgs::default(),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        let (req_path, key_source) =
            create_cert::run(&opts, &passphrase_reader, default_directory.path()).unwrap();

        assert_eq!(
            req_path.parent().unwrap(),
            default_directory.path(),
            "Request should be saved to the default directory"
        );

        match key_source {
            KeySource::NewKey(NewKeyDetails {
                priv_path,
                pub_path,
                ..
            }) => {
                assert_eq!(
                    priv_path.parent().unwrap(),
                    default_directory.path(),
                    "Private key should be saved to the default directory"
                );
                assert_eq!(
                    pub_path.parent().unwrap(),
                    default_directory.path(),
                    "Public key should be saved to the default directory"
                );
            }
            _ => panic!("key should have been saved"),
        }
    }

    #[test]
    fn can_create_request_with_public_key_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("leaf.certr");
        let default_dir = temp_path.join("default/");
        let pub_key_path = temp_path.join("key.pub");

        let kp = KeyPair::new_random();
        save_public_key_to_file(kp.public_key(), &pub_key_path).unwrap();

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Leaf,
            role: RoleKind::Exemption,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: false,
            key: AssociatedKeyArgs::key_from_file(pub_key_path),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect("could not create leaf exemption certificate request");

        assert!(request_path.exists());

        let request = load_cert_request_from_file::<Exemption>(&request_path)
            .expect("should have been able to load request");
        assert_eq!(request.public_key(), &kp.public_key())
    }

    #[test]
    fn can_create_request_with_public_key_from_hex() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("leaf.certr");
        let default_dir = temp_path.join("default/");

        let kp = KeyPair::new_random();
        let hex = kp.public_key().to_string();

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Leaf,
            role: RoleKind::Exemption,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: false,
            key: AssociatedKeyArgs::key_from_hex(hex),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect("could not create leaf exemption certificate request");

        assert!(request_path.exists());

        let request = load_cert_request_from_file::<Exemption>(&request_path)
            .expect("should have been able to load request");
        assert_eq!(request.public_key(), &kp.public_key())
    }

    #[test]
    fn can_correctly_set_email_and_name_on_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("root.certr");
        let default_dir = temp_path.join("default/");

        let name = "E Xample";
        let email = "e@xample.com";

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: Some(name.into()),
            email: Some(email.into()),
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: false,
            key: AssociatedKeyArgs::default(),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir).unwrap();

        assert!(request_path.exists());

        let request = load_cert_request_from_file::<Manufacturer>(&request_path).unwrap();
        let json_display = SingleRequestOutput(request)
            .format(&FormatMethod::JsonDigest)
            .unwrap();
        let digest: RequestDigest = serde_json::from_str(&json_display).unwrap();

        assert!(digest.subject.desc.contains(name) && digest.subject.desc.contains(email));
    }

    #[test]
    fn can_create_cert_request_using_env_passphrase_reader() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("1234.certr");
        let key_path = temp_path.join("1234.priv");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: false,
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        let passphrase_reader = EnvVarPassphraseReader;
        let test_passphrase = "test_passphrase";

        let (path, key_source) = temp_env::with_var(
            KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
            Some(test_passphrase),
            || create_cert::run(&opts, &passphrase_reader, &default_dir),
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
    fn warning_printed_to_stderr_on_creating_cert_request_using_env_passphrase_reader() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("1234.certr");
        let key_path = temp_path.join("1234.priv");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path),
            notify: vec![],
            allow_blinding: false,
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
                create_cert::main(
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
    fn create_cert_request_using_env_passphrase_reader_fails_gracefully_if_env_variable_not_present(
    ) {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("1234.certr");
        let key_path = temp_path.join("1234.priv");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: false,
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
        };

        let passphrase_reader = EnvVarPassphraseReader;

        let err = temp_env::with_var_unset(KEY_ENCRYPTION_PASSPHRASE_ENV_VAR, || {
            create_cert::run(&opts, &passphrase_reader, &default_dir)
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
    fn default_dir_is_created_if_not_present_where_no_output_paths_specified() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: None,
            key: AssociatedKeyArgs::default(),
            notify: vec![],
            allow_blinding: false,
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir).unwrap();

        assert!(default_dir.exists())
    }

    #[test]
    fn default_dir_is_created_if_not_present_where_no_request_output_is_supplied() {
        let temp_dir = TempDir::new().unwrap();
        let default_dir = temp_dir.path().join("default/");
        let key_path = temp_dir.path().join("key.priv");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: None,
            key: AssociatedKeyArgs::create_key_at_path(key_path),
            notify: vec![],
            allow_blinding: false,
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir).unwrap();

        assert!(default_dir.exists())
    }

    #[test]
    fn default_dir_is_not_created_if_not_required_due_to_custom_output_paths() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("1234.certr");
        let key_path = temp_path.join("key.priv");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path),
            key: AssociatedKeyArgs::create_key_at_path(key_path),
            notify: vec![],
            allow_blinding: false,
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir).unwrap();

        assert!(!default_dir.exists())
    }

    #[test]
    fn if_correct_extension_is_present_no_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("1234.certr");
        let key_path = temp_path.join("key.priv");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
            notify: vec![],
            allow_blinding: false,
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        let (actual_request_path, actual_key_source) =
            create_cert::run(&opts, &passphrase_reader, &default_dir).unwrap();

        let expected_key_source = KeySource::NewKey(NewKeyDetails {
            pub_path: key_path.with_extension(KEY_PUB_EXT),
            priv_path: key_path,
            passphrase_source: PassphraseSource::Memory,
        });

        assert_eq!(expected_key_source, actual_key_source);
        assert_eq!(request_path, actual_request_path);
    }

    #[test]
    fn if_correct_extension_is_not_present_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("1234");
        let key_path = temp_path.join("key");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            key: AssociatedKeyArgs::create_key_at_path(key_path.clone()),
            notify: vec![],
            allow_blinding: false,
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        let (actual_request_path, actual_key_source) =
            create_cert::run(&opts, &passphrase_reader, &default_dir).unwrap();

        let expected_key_source = KeySource::NewKey(NewKeyDetails {
            pub_path: key_path.with_extension(KEY_PUB_EXT),
            priv_path: key_path.with_extension(KEY_PRIV_EXT),
            passphrase_source: PassphraseSource::Memory,
        });

        assert_eq!(expected_key_source, actual_key_source);
        assert_eq!(
            request_path.with_extension(CERT_REQUEST_EXT),
            actual_request_path
        );
    }

    #[test]
    fn pub_key_extension_is_added_if_not_present() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let request_path = temp_path.join("1234.certr");
        let key_path = temp_path.join("key");

        let kp = KeyPair::new_random();
        save_public_key_to_file(kp.public_key(), &key_path.with_extension(KEY_PUB_EXT)).unwrap();

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Root,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path),
            key: AssociatedKeyArgs::key_from_file(key_path),
            notify: vec![],
            allow_blinding: false,
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect("should have inferred .pub key extension");
    }

    #[test]
    fn can_set_blinding_allowed_on_exemption_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("leaf.certr");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Leaf,
            role: RoleKind::Exemption,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: true,
            key: AssociatedKeyArgs::default(),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect("could not create leaf exemption certificate request");

        assert!(request_path.exists());

        let cert = load_cert_request_from_file::<Exemption>(&request_path).unwrap();
        assert!(cert.blinding_allowed())
    }

    #[test]
    fn cannot_set_blinding_allowed_on_infrastructure_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("leaf.certr");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Leaf,
            role: RoleKind::Infrastructure,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: true,
            key: AssociatedKeyArgs::default(),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        let err = create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect_err("shouldn't be possible to set 'allow blinding' on an infrastructure cert");

        assert_eq!(err, CertCliError::AllowBlindingNotAllowed);
    }

    #[test]
    fn cannot_set_blinding_allowed_on_manufacturer_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("leaf.certr");
        let default_dir = temp_path.join("default/");

        let opts = CreateCertOpts {
            hierarchy: HierarchyKind::Leaf,
            role: RoleKind::Manufacturer,
            name: None,
            email: None,
            output: Some(request_path.clone()),
            notify: vec![],
            allow_blinding: true,
            key: AssociatedKeyArgs::default(),
        };

        let passphrase_reader = MemoryPassphraseReader::default();

        let err = create_cert::run(&opts, &passphrase_reader, &default_dir)
            .expect_err("shouldn't be possible to set 'allow blinding' on a manufacturer cert");

        assert_eq!(err, CertCliError::AllowBlindingNotAllowed);
    }
}
