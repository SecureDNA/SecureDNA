// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for merging two certificates which are derived from the same certificate request

use std::path::Path;
use std::{io::Write, path::PathBuf};

use certificates::file::CERT_EXT;
use certificates::{
    file::{load_certificate_bundle_from_file, save_certificate_bundle_to_file},
    Exemption, Infrastructure, Manufacturer, Role, RoleKind,
};
use clap::{crate_version, Parser};

use super::error::CertCliError;
use crate::default_filepath::{
    get_default_filename_for_cert_bundle,
    set_appropriate_filepath_and_create_default_dir_if_required,
};

#[derive(Debug, Parser)]
#[clap(
    name = "sdna-merge-cert",
    about = "A tool to merge two certificate files which are derived from the same certificate request.",
    version = crate_version!()
)]
pub struct MergeCertOpts {
    #[clap(
        help = "Role of certificate(s) [possible values: exemption, infrastructure, manufacturer]"
    )]
    pub role: RoleKind,
    #[clap(help = "Filepath where first certificate to merge can be found")]
    pub cert_1: PathBuf,
    #[clap(help = "Filepath where second certificate to merge can be found")]
    pub cert_2: PathBuf,
    #[clap(
        long,
        help = "Filepath where new certificate will be saved (optional). If this is not provided it will be derived from the original certificate filepath."
    )]
    pub output: Option<PathBuf>,
}

pub fn main<W: Write, E: Write>(
    opts: &MergeCertOpts,
    default_directory: &Path,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<(), std::io::Error> {
    match run(opts, default_directory) {
        Ok(filepath) => writeln!(
            stdout,
            "Cross-signed certificate has been saved to {}",
            filepath.display()
        ),
        Err(err) => writeln!(stderr, "{err}"),
    }
}

fn run(opts: &MergeCertOpts, default_directory: &Path) -> Result<PathBuf, CertCliError> {
    match opts.role {
        RoleKind::Exemption => merge_certs::<Exemption>(opts, default_directory),
        RoleKind::Infrastructure => merge_certs::<Infrastructure>(opts, default_directory),
        RoleKind::Manufacturer => merge_certs::<Manufacturer>(opts, default_directory),
    }
}

fn merge_certs<R: Role>(
    opts: &MergeCertOpts,
    default_directory: &Path,
) -> Result<PathBuf, CertCliError> {
    let cert_1 = match opts.cert_1.extension() {
        Some(_) => opts.cert_1.to_owned(),
        None => opts.cert_1.with_extension(CERT_EXT),
    };
    let cert_2 = match opts.cert_2.extension() {
        Some(_) => opts.cert_2.to_owned(),
        None => opts.cert_2.with_extension(CERT_EXT),
    };

    let cb_1 = load_certificate_bundle_from_file::<R>(&cert_1)?;
    let cb_2 = load_certificate_bundle_from_file::<R>(&cert_2)?;

    let new_cb = cb_1
        .merge(cb_2)
        .map_err(|_| CertCliError::CouldNotMerge(opts.cert_1.to_owned(), opts.cert_2.to_owned()))?;

    // If no destination is provided for the cross-signed certificate then we use the directory
    // of the original certificate.
    let cert_path = set_appropriate_filepath_and_create_default_dir_if_required(
        opts.output.as_ref(),
        CERT_EXT,
        || {
            opts.cert_1
                .with_file_name(get_default_filename_for_cert_bundle(&new_cb))
        },
        default_directory,
    )?;

    save_certificate_bundle_to_file(new_cb, &cert_path)?;
    Ok(cert_path)
}

#[cfg(test)]
mod tests {
    use certificates::file::CERT_EXT;
    use certificates::test_helpers::create_intermediate_bundle;
    use certificates::{
        file::{load_certificate_bundle_from_file, save_certificate_bundle_to_file},
        test_helpers, Builder, CertificateBundle, Infrastructure, IssuerAdditionalFields, KeyPair,
        Manufacturer, RequestBuilder, RoleKind,
    };
    use std::path::Path;
    use tempfile::TempDir;

    use crate::shims::{
        error::CertCliError,
        merge_cert::{self, MergeCertOpts},
    };

    #[test]
    fn cannot_merge_certs_which_are_not_derived_from_the_same_certificate_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_dir.path().join("default/");
        let int_a_path = temp_path.join("int_a.cert");
        let int_b_path = temp_path.join("int_b.cert");
        let int_cert_path = temp_dir.path().join("int.cert");

        let (int_a, _, _) = test_helpers::create_intermediate_bundle::<Infrastructure>();
        let (int_b, _, _) = test_helpers::create_intermediate_bundle::<Infrastructure>();

        save_certificate_bundle_to_file(int_a, &int_a_path).unwrap();
        save_certificate_bundle_to_file(int_b, &int_b_path).unwrap();

        let opts = MergeCertOpts {
            role: RoleKind::Infrastructure,
            cert_1: int_a_path,
            cert_2: int_b_path,
            output: Some(int_cert_path),
        };

        let result = merge_cert::run(&opts, &default_dir);
        match result {
            Ok(_) => panic!(
                "should not be able to create cross signed certificate \
                from certificates derived from different requests"
            ),
            Err(err) => assert_eq!(err, CertCliError::CouldNotMerge(opts.cert_1, opts.cert_2)),
        };
    }

    #[test]
    fn merged_certificate_contains_original_certificates() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let int_a_path = temp_path.join("int_a.cert");
        let int_b_path = temp_path.join("int_b.cert");
        let int_path = temp_dir.path().join("int.cert");

        let root_kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Manufacturer>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();
        let root_bundle = CertificateBundle::new(root_cert, None);

        let int_kp = KeyPair::new_random();
        let int_req_a =
            RequestBuilder::<Manufacturer>::intermediate_v1_builder(int_kp.public_key()).build();
        let int_req_b = int_req_a.clone();

        let int_bundle_a = root_bundle
            .issue_cert_bundle(
                int_req_a,
                IssuerAdditionalFields::default(),
                root_kp.clone(),
            )
            .expect("Couldn't issue cert bundle");

        let int_bundle_b = root_bundle
            .issue_cert_bundle(int_req_b, IssuerAdditionalFields::default(), root_kp)
            .expect("Couldn't issue cert bundle");

        let int_cert_a = int_bundle_a.certs[0].clone();
        let int_cert_b = int_bundle_b.certs[0].clone();

        save_certificate_bundle_to_file(int_bundle_a, &int_a_path).unwrap();
        save_certificate_bundle_to_file(int_bundle_b, &int_b_path).unwrap();

        let opts = MergeCertOpts {
            role: RoleKind::Manufacturer,
            cert_1: int_a_path,
            cert_2: int_b_path,
            output: Some(int_path.clone()),
        };

        merge_cert::run(&opts, &default_dir).unwrap();
        let merged_cert = load_certificate_bundle_from_file::<Manufacturer>(&int_path).unwrap();
        assert!(merged_cert.certs.contains(&int_cert_a));
        assert!(merged_cert.certs.contains(&int_cert_b));
    }

    #[test]
    fn default_directory_is_created_if_not_present_and_required_for_output() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_dir.path().join("default/");
        let int_a_path = temp_path.join("int_a.cert");
        let int_b_path = temp_path.join("int_b.cert");
        let output = default_dir.join("int.cert");

        create_mergable_certificate_bundles(&int_a_path, &int_b_path);

        let opts = MergeCertOpts {
            role: RoleKind::Infrastructure,
            cert_1: int_a_path,
            cert_2: int_b_path,
            output: Some(output.clone()),
        };

        merge_cert::run(&opts, &default_dir).expect("could not merge certs");

        assert!(default_dir.exists());
    }

    #[test]
    fn default_directory_is_not_created_if_not_required() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_dir.path().join("default/");
        let int_a_path = temp_path.join("int_a.cert");
        let int_b_path = temp_path.join("int_b.cert");
        let output = temp_path.join("int.cert");

        create_mergable_certificate_bundles(&int_a_path, &int_b_path);

        let opts = MergeCertOpts {
            role: RoleKind::Infrastructure,
            cert_1: int_a_path,
            cert_2: int_b_path,
            output: Some(output.clone()),
        };

        merge_cert::run(&opts, &default_dir).expect("could not merge certs");

        assert!(!default_dir.exists());
    }

    #[test]
    fn if_correct_extension_is_present_no_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let int_a_path = temp_path.join("int_a.cert");
        let int_b_path = temp_path.join("int_b.cert");
        let cert_path = temp_path.join("int.cert");

        create_mergable_certificate_bundles(&int_a_path, &int_b_path);

        let opts = MergeCertOpts {
            role: RoleKind::Infrastructure,
            cert_1: int_a_path,
            cert_2: int_b_path,
            output: Some(cert_path.clone()),
        };

        let actual_cert_path = merge_cert::run(&opts, &default_dir).expect("could not merge certs");

        assert_eq!(cert_path, actual_cert_path);
    }

    #[test]
    fn if_correct_extension_is_not_present_extension_is_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let int_a_path = temp_path.join("int_a.cert");
        let int_b_path = temp_path.join("int_b.cert");
        let cert_path = temp_path.join("int");

        create_mergable_certificate_bundles(&int_a_path, &int_b_path);

        let opts = MergeCertOpts {
            role: RoleKind::Infrastructure,
            cert_1: int_a_path,
            cert_2: int_b_path,
            output: Some(cert_path.clone()),
        };

        let actual_cert_path = merge_cert::run(&opts, &default_dir).expect("could not merge certs");

        assert_eq!(cert_path.with_extension(CERT_EXT), actual_cert_path);
    }

    fn create_mergable_certificate_bundles(int_a_path: &Path, int_b_path: &Path) {
        let (int_bundle_a, _, _) = create_intermediate_bundle::<Infrastructure>();
        let int_req = int_bundle_a.certs[0].request();

        let kp = KeyPair::new_random();
        let root_b = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();
        let root_bundle_b = CertificateBundle::new(root_b, None);

        let int_bundle_b = root_bundle_b
            .issue_cert_bundle(int_req, IssuerAdditionalFields::default(), kp)
            .unwrap();

        save_certificate_bundle_to_file(int_bundle_a, int_a_path).unwrap();
        save_certificate_bundle_to_file(int_bundle_b, int_b_path).unwrap();
    }

    #[test]
    fn can_infer_correct_extension() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let default_dir = temp_path.join("default/");
        let int_a_path = temp_path.join("int_a");
        let int_b_path = temp_path.join("int_b");
        let cert_path = temp_path.join("int.cert");

        create_mergable_certificate_bundles(
            &int_a_path.with_extension(CERT_EXT),
            &int_b_path.with_extension(CERT_EXT),
        );

        let opts = MergeCertOpts {
            role: RoleKind::Infrastructure,
            cert_1: int_a_path,
            cert_2: int_b_path,
            output: Some(cert_path),
        };

        merge_cert::run(&opts, &default_dir).expect("should have inferred extensions");
    }
}
