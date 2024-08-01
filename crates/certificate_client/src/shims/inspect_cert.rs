// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for inspecting the contents of a certificate or certificate request

use std::{io::Write, path::PathBuf};

use clap::{crate_version, Parser, Subcommand};

use crate::inspect::{
    ChainViewMode, FormatMethod, Formattable, MultiItemOutput, SingleRequestOutput,
};

use super::error::CertCliError;

use certificates::file::{CERT_EXT, CERT_REQUEST_EXT};
use certificates::{
    file::{load_cert_request_from_file, load_certificate_bundle_from_file},
    Exemption, Infrastructure, Manufacturer, Role, RoleKind,
};

#[derive(Debug, Parser)]
#[clap(
    name = "sdna-inspect-cert",
    about = "Inspects and validates a SecureDNA certificate, certificate request, or certificate chain",
    version = crate_version!()
)]

pub struct InspectCertOpts {
    #[clap(subcommand)]
    pub target: Target,
    #[clap(
        global = true,
        long,
        help = "How to display results [default: plain-digest] [possible values: plain-digest, json-digest, json-full]",
        default_value = "plain-digest"
    )]
    pub format: FormatMethod,
    #[clap(
        help = "Role of certificate(s) [possible values: exemption, infrastructure, manufacturer]"
    )]
    pub role: RoleKind,
}
/// The data type being inspected
#[derive(Debug, Subcommand)]
pub enum Target {
    /// Inspect a certificate request
    ///
    Request {
        #[clap(help = "Path of certificate request to be inspected")]
        file: PathBuf,
    },
    /// Inspect a certificate
    Cert {
        #[clap(help = "Path of certificate with chain to be inspected")]
        file: PathBuf,
    },
    // Inspect a certificate chain
    Chain {
        #[clap(help = "Path of certificate with chain to be inspected")]
        file: PathBuf,
        #[clap(subcommand)]
        view_mode: ChainViewMode,
    },
}

pub fn main<W: Write, E: Write>(
    opts: &InspectCertOpts,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<(), std::io::Error> {
    match run(opts) {
        Ok(display_text) => {
            writeln!(stdout, "{display_text}")?;
            Ok(())
        }
        Err(err) => writeln!(stderr, "{err}"),
    }
}

fn run(opts: &InspectCertOpts) -> Result<String, CertCliError> {
    match opts.role {
        RoleKind::Exemption => inspect_file::<Exemption>(opts),
        RoleKind::Infrastructure => inspect_file::<Infrastructure>(opts),
        RoleKind::Manufacturer => inspect_file::<Manufacturer>(opts),
    }
}

fn inspect_file<R: Role>(opts: &InspectCertOpts) -> Result<String, CertCliError> {
    let format_method = &opts.format;

    let display_text = match &opts.target {
        Target::Request { file } => {
            let file = match file.extension() {
                Some(_) => file.to_owned(),
                None => file.with_extension(CERT_REQUEST_EXT),
            };
            let request = load_cert_request_from_file::<R>(&file)?;
            SingleRequestOutput(request)
                .format(format_method)
                .map_err(CertCliError::from)
        }
        Target::Cert { file } => {
            let file = match file.extension() {
                Some(_) => file.to_owned(),
                None => file.with_extension(CERT_EXT),
            };
            let cert_bundle = load_certificate_bundle_from_file::<R>(&file)?;
            MultiItemOutput::from_items(cert_bundle.certs)
                .format(format_method)
                .map_err(CertCliError::from)
        }
        Target::Chain { file, view_mode } => {
            let file = match file.extension() {
                Some(_) => file.to_owned(),
                None => file.with_extension(CERT_EXT),
            };
            let cert_bundle = load_certificate_bundle_from_file::<R>(&file)?;
            view_mode.display_chain(cert_bundle, format_method)
        }
    }?;

    Ok(display_text)
}

#[cfg(test)]
mod tests {

    use certificates::file::{
        save_cert_request_to_file, save_certificate_bundle_to_file, CERT_EXT, CERT_REQUEST_EXT,
    };
    use certificates::{
        test_helpers, Builder, CertificateBundle, Digestible, Exemption, IssuerAdditionalFields,
        KeyPair, RequestBuilder, RoleKind,
    };
    use tempfile::TempDir;

    use crate::inspect::FormatMethod;
    use crate::{
        inspect::ChainViewMode,
        shims::inspect_cert::{self, InspectCertOpts, Target},
    };

    #[test]
    fn inspection_of_leaf_cert_chain_reveals_issuing_intermediate_cert() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let leaf_cert_path = temp_path.join("leaf.cert");

        let (int_bundle, int_kp, _) = test_helpers::create_intermediate_bundle::<Exemption>();

        let leaf_request =
            RequestBuilder::<Exemption>::leaf_v1_builder(KeyPair::new_random().public_key())
                .build();

        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_request, IssuerAdditionalFields::default(), int_kp)
            .unwrap();

        save_certificate_bundle_to_file(leaf_bundle, &leaf_cert_path).unwrap();

        let opts = InspectCertOpts {
            role: RoleKind::Exemption,
            format: FormatMethod::PlainDigest,
            target: Target::Chain {
                file: leaf_cert_path,
                view_mode: ChainViewMode::AllCerts,
            },
        };

        let inspect_chain_display =
            inspect_cert::run(&opts).expect("inspecting leaf certificate failed");

        let expected_display_text = int_bundle.certs[0].clone().into_digest().to_string();

        assert_eq!(inspect_chain_display, expected_display_text)
    }

    #[test]
    fn inspect_shows_multiple_paths_to_root_where_leaf_was_signed_by_cross_signed_intermediate() {
        let temp_dir = TempDir::new().unwrap();
        let leaf_cert_path = temp_dir.path().join("leaf.cert");

        let root_kp = KeyPair::new_random();
        let root_public_key = root_kp.public_key();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();
        let root_bundle = CertificateBundle::new(root_cert, None);

        let int_kp = KeyPair::new_random();
        let int_req_a =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();
        let int_req_b = int_req_a.clone();

        let int_bundle_a = root_bundle
            .issue_cert_bundle(
                int_req_a,
                IssuerAdditionalFields::default(),
                root_kp.clone(),
            )
            .unwrap();
        let int_bundle_b = root_bundle
            .issue_cert_bundle(
                int_req_b,
                IssuerAdditionalFields::default(),
                root_kp.clone(),
            )
            .unwrap();
        let int_bundle = int_bundle_a.merge(int_bundle_b).unwrap();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();
        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_req, IssuerAdditionalFields::default(), int_kp)
            .unwrap();
        save_certificate_bundle_to_file(leaf_bundle, &leaf_cert_path).unwrap();

        let opts = InspectCertOpts {
            role: RoleKind::Exemption,
            format: FormatMethod::PlainDigest,
            target: Target::Chain {
                file: leaf_cert_path,
                view_mode: ChainViewMode::AllPaths {
                    public_keys: vec![root_public_key],
                },
            },
        };

        let display_text = inspect_cert::run(&opts).unwrap();

        assert!(display_text.contains("Path 1"));
        assert!(display_text.contains("Path 2"));
        assert!(!display_text.contains("Path 3"));
    }

    #[test]
    fn inspect_request_infers_extension_if_not_provided() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("root");

        let kp = KeyPair::new_random();
        let request = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key()).build();
        save_cert_request_to_file(request, &request_path.with_extension(CERT_REQUEST_EXT)).unwrap();

        let opts = InspectCertOpts {
            role: RoleKind::Exemption,
            format: FormatMethod::PlainDigest,
            target: Target::Request { file: request_path },
        };

        inspect_cert::run(&opts).expect("inspect tool should be able to infer request extension");
    }

    #[test]
    fn inspect_cert_infers_extension_if_not_provided() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("root");

        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();
        save_certificate_bundle_to_file(
            CertificateBundle::new(cert, None),
            &cert_path.with_extension(CERT_EXT),
        )
        .unwrap();

        let opts = InspectCertOpts {
            role: RoleKind::Exemption,
            format: FormatMethod::PlainDigest,
            target: Target::Cert { file: cert_path },
        };

        inspect_cert::run(&opts)
            .expect("inspect tool should be able to infer certificate extension");
    }

    #[test]
    fn inspect_cert_chain_infers_extension_if_not_provided() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("root");

        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();
        save_certificate_bundle_to_file(
            CertificateBundle::new(cert, None),
            &cert_path.with_extension(CERT_EXT),
        )
        .unwrap();

        let opts = InspectCertOpts {
            role: RoleKind::Exemption,
            format: FormatMethod::PlainDigest,
            target: Target::Chain {
                file: cert_path,
                view_mode: ChainViewMode::AllCerts,
            },
        };

        inspect_cert::run(&opts)
            .expect("inspect tool should be able to infer certificate extension");
    }
}
