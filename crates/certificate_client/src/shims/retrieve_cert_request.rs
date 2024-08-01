// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{io::Write, path::PathBuf};

use clap::{crate_version, Parser};

use certificates::file::{
    load_certificate_bundle_from_file, save_cert_request_to_file, CERT_EXT, CERT_REQUEST_EXT,
};
use certificates::{Exemption, Infrastructure, Manufacturer, Role, RoleKind};

use super::error::CertCliError;

#[derive(Debug, Parser)]
#[clap(
name = "sdna-retrieve-cert-request",
about = "Retrieves the original certificate request from a certificate",
version = crate_version!()
)]
pub struct RetrieveRequestOpts {
    #[clap(
        help = "Role of certificate [possible values: exemption, infrastructure, manufacturer]"
    )]
    pub role: RoleKind,
    #[clap(help = "Filepath where certificate can be found")]
    cert: PathBuf,
    #[clap(
        long,
        help = "Filepath where the request will be saved (optional). If this is not provided it will be derived from the certificate filepath"
    )]
    pub output: Option<PathBuf>,
}

pub fn main<W, E>(
    opts: &RetrieveRequestOpts,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<(), std::io::Error>
where
    W: Write,
    E: Write,
{
    match run(opts) {
        Ok(output) => {
            writeln!(stdout, "Saved certificate request to {}", output.display())
        }
        Err(err) => writeln!(stderr, "{err}"),
    }
}

fn run(opts: &RetrieveRequestOpts) -> Result<PathBuf, CertCliError> {
    match opts.role {
        RoleKind::Exemption => retrieve_request::<Exemption>(opts),
        RoleKind::Infrastructure => retrieve_request::<Infrastructure>(opts),
        RoleKind::Manufacturer => retrieve_request::<Manufacturer>(opts),
    }
}

fn retrieve_request<R: Role>(opts: &RetrieveRequestOpts) -> Result<PathBuf, CertCliError> {
    let output = opts
        .output
        .clone()
        .unwrap_or_else(|| opts.cert.with_extension(CERT_REQUEST_EXT));

    let cert = match opts.cert.extension() {
        Some(_) => opts.cert.to_owned(),
        None => opts.cert.with_extension(CERT_EXT),
    };

    let request = load_certificate_bundle_from_file::<R>(&cert)?
        .get_lead_cert()
        .unwrap()
        .request()
        .clone();

    save_cert_request_to_file(request, &output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use crate::shims::retrieve_cert_request::{run, RetrieveRequestOpts};
    use certificates::file::{
        save_cert_request_to_file, save_certificate_bundle_to_file, CERT_EXT,
    };
    use certificates::test_helpers::create_intermediate_bundle;
    use certificates::{
        Builder, CertificateBundle, Description, Exemption, Infrastructure, IssuerAdditionalFields,
        KeyPair, Manufacturer, RequestBuilder, RoleKind,
    };
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn can_retrieve_exemption_root_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let cert_path = temp_path.join("root.cert");
        let req_path = temp_path.join("root_a.certr");
        let retrieved_req_path = temp_path.join("root_b.certr");

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .with_description(
                Description::default()
                    .with_name("Mr Test")
                    .with_email("test@example.com")
                    .with_phone_number("12345678901")
                    .with_orcid("888"),
            )
            .build();

        let cert = req
            .clone()
            .load_key(kp)
            .unwrap()
            .self_sign(
                IssuerAdditionalFields::default().with_emails_to_notify(vec!["test2@example.com"]),
            )
            .unwrap();

        save_cert_request_to_file(req, &req_path).unwrap();
        save_certificate_bundle_to_file(CertificateBundle::new(cert, None), &cert_path).unwrap();

        let opts = RetrieveRequestOpts {
            role: RoleKind::Exemption,
            cert: cert_path,
            output: Some(retrieved_req_path.clone()),
        };

        run(&opts).expect("retrieve cert request failed");

        let request_file_contents = fs::read_to_string(&req_path).unwrap();
        let retrieved_request_file_contents = fs::read_to_string(&retrieved_req_path).unwrap();

        assert_eq!(request_file_contents, retrieved_request_file_contents)
    }

    #[test]
    fn can_retrieve_infrastructure_intermediate_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let cert_path = temp_path.join("int.cert");
        let req_path = temp_path.join("int_a.certr");
        let retrieved_req_path = temp_path.join("int_b.certr");

        let root_kp = KeyPair::new_random();
        let root = RequestBuilder::<Infrastructure>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let root_bundle = CertificateBundle::new(root, None);

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Infrastructure>::intermediate_v1_builder(int_kp.public_key())
                .with_description(
                    Description::default()
                        .with_name("Mr Test")
                        .with_email("test@example.com")
                        .with_phone_number("12345678901"),
                )
                .build();

        let int_bundle = root_bundle
            .issue_cert_bundle(int_req.clone(), IssuerAdditionalFields::default(), root_kp)
            .unwrap();

        save_cert_request_to_file(int_req, &req_path).unwrap();
        save_certificate_bundle_to_file(int_bundle, &cert_path).unwrap();

        let opts = RetrieveRequestOpts {
            role: RoleKind::Infrastructure,
            cert: cert_path,
            output: Some(retrieved_req_path.clone()),
        };

        run(&opts).expect("retreive cert request failed");

        let request_file_contents = fs::read_to_string(&req_path).unwrap();
        let retrieved_request_file_contents = fs::read_to_string(&retrieved_req_path).unwrap();

        assert_eq!(request_file_contents, retrieved_request_file_contents)
    }

    #[test]
    fn can_retrieve_manufacturer_leaf_request() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let cert_path = temp_path.join("leaf.cert");
        let req_path = temp_path.join("leaf_a.certr");
        let retrieved_req_path = temp_path.join("leaf_b.certr");

        let (int_bundle, kp, _) = create_intermediate_bundle::<Manufacturer>();

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Manufacturer>::leaf_v1_builder(leaf_kp.public_key())
            .with_description(
                Description::default()
                    .with_name("Mr Test")
                    .with_email("test@example.com")
                    .with_phone_number("12345678901"),
            )
            .build();

        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_req.clone(), IssuerAdditionalFields::default(), kp)
            .unwrap();

        save_cert_request_to_file(leaf_req, &req_path).unwrap();
        save_certificate_bundle_to_file(leaf_bundle, &cert_path).unwrap();

        let opts = RetrieveRequestOpts {
            role: RoleKind::Manufacturer,
            cert: cert_path,
            output: Some(retrieved_req_path.clone()),
        };

        run(&opts).expect("retreive cert request failed");

        let request_file_contents = fs::read_to_string(&req_path).unwrap();
        let retrieved_request_file_contents = fs::read_to_string(&retrieved_req_path).unwrap();

        assert_eq!(request_file_contents, retrieved_request_file_contents)
    }

    #[test]
    fn can_infer_cert_extension() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let cert_path = temp_path.join("root");
        let retrieved_req_path = temp_path.join("root.certr");

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

        let opts = RetrieveRequestOpts {
            role: RoleKind::Exemption,
            cert: cert_path,
            output: Some(retrieved_req_path),
        };

        run(&opts).expect("should have inferred extension correctly");
    }
}
