// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::validation_failure::ValidationFailure;
use crate::{
    certificate::inner::{CertificateInner, HierarchyLevel, Issuer, RequestInner, Subject},
    issued::Issued,
    keypair::Signature,
    shared_components::{
        common::{CompatibleIdentity, Expiration, Id},
        digest::{INDENT, INDENT2},
        role::Role,
    },
    utility::combine_and_dedup_items,
};

use super::{
    version_wrappers::{CertificateVersion, RequestVersion},
    Certificate, CertificateRequest,
};

/// Contains fields useful for inspecting the certificate
#[derive(Serialize)]
pub struct CertificateDigest {
    pub version: String,
    pub issued_to: CompatibleIdentity,
    pub request_id: Id,
    pub issued_by: CompatibleIdentity,
    pub issuance_id: Id,
    pub expiration: Expiration,
    pub signature: Signature,
    pub validation_failure: Option<ValidationFailure>,
    pub emails_to_notify: Vec<String>,
}

impl<R, K> From<Certificate<R, K>> for CertificateDigest
where
    R: Role,
{
    fn from(value: Certificate<R, K>) -> Self {
        let validation_failure = value.validate().err();
        let role = capitalize_first(R::DESCRIPTION);
        match value.version {
            CertificateVersion::RootV1(inner) => {
                let version = format!("Root V1 {role}");
                CertificateDigest::new(version, inner, validation_failure)
            }
            CertificateVersion::IntermediateV1(inner) => {
                let version = format!("Intermediate V1 {role}");
                CertificateDigest::new(version, inner, validation_failure)
            }
            CertificateVersion::LeafV1(inner) => {
                let version = format!("Leaf V1 {role}");
                CertificateDigest::new(version, inner, validation_failure)
            }
        }
    }
}

impl fmt::Display for CertificateDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} Certificate", self.version)?;
        writeln!(f, "{:INDENT$}Issuance ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issuance_id)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Issued to:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issued_to)?;
        writeln!(f, "{:INDENT$}Issued by:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issued_by)?;
        write!(f, "{}", self.expiration)?;
        writeln!(f, "{:INDENT$}Signature:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.signature)?;

        if !self.emails_to_notify.is_empty() {
            writeln!(f, "{:INDENT$}Emails to notify:", "")?;
            for email in &self.emails_to_notify {
                writeln!(f, "{:INDENT2$}{}", "", email)?;
            }
        }
        if let Some(validation_failure) = &self.validation_failure {
            writeln!(f)?;
            write!(f, "{}", validation_failure)?;
        }
        Ok(())
    }
}

impl CertificateDigest {
    fn new<T, R, S, I>(
        version: String,
        inner: CertificateInner<T, R, S, I>,
        validation_failure: Option<ValidationFailure>,
    ) -> Self
    where
        R: Role,
        S: Subject,
        I: Issuer,
    {
        let signature = inner.0.signature;
        let expiration = inner.0.data.common.issuer.expiration().clone();
        let request_id = *inner.0.data.common.subject.request_id();
        let issued_to: CompatibleIdentity = inner.0.data.common.subject.to_compatible_identity();
        let issuance_id = *inner.0.data.common.issuer.issuance_id();
        let issued_by: CompatibleIdentity = inner.0.data.common.issuer.to_compatible_identity();

        let notify_emails = inner.0.data.common.subject.emails_to_notify();
        let additional_notify_emails = inner.0.data.common.issuer.additional_emails_to_notify();
        let emails_to_notify = combine_and_dedup_items(notify_emails, additional_notify_emails);

        Self {
            version,
            issued_to,
            issued_by,
            expiration,
            signature,
            request_id,
            issuance_id,
            emails_to_notify,
            validation_failure,
        }
    }
}

/// Contains fields useful for inspecting the certificate request
#[derive(Serialize, Deserialize)]
pub struct RequestDigest {
    pub version: String,
    pub request_id: Id,
    pub subject: CompatibleIdentity,
    pub emails_to_notify: Vec<String>,
}

impl<R, K> From<CertificateRequest<R, K>> for RequestDigest
where
    R: Role,
{
    fn from(value: CertificateRequest<R, K>) -> Self {
        let role = capitalize_first(R::DESCRIPTION);
        match value.version {
            RequestVersion::RootV1(inner) => {
                let version = format!("Root V1 {role}");
                Self::from_version_and_request_inner(version, inner)
            }
            RequestVersion::IntermediateV1(inner) => {
                let version = format!("Intermediate V1 {role}");
                Self::from_version_and_request_inner(version, inner)
            }
            RequestVersion::LeafV1(inner) => {
                let version = format!("Leaf V1 {role}");
                Self::from_version_and_request_inner(version, inner)
            }
        }
    }
}

impl RequestDigest {
    fn from_version_and_request_inner<T: HierarchyLevel, R: Role, S: Subject>(
        version: String,
        inner: RequestInner<T, R, S>,
    ) -> Self {
        let request_id = *inner.subject.request_id();
        let subject = inner.subject.to_compatible_identity();
        let emails_to_notify = inner.subject.emails_to_notify().to_vec();
        Self {
            version,
            request_id,
            subject,
            emails_to_notify,
        }
    }
}

impl fmt::Display for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} Certificate Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Subject:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.subject)?;
        if !self.emails_to_notify.is_empty() {
            writeln!(f, "{:INDENT$}Emails to notify:", "")?;
            for email in &self.emails_to_notify {
                writeln!(f, "{:INDENT2$}{}", "", email)?;
            }
        }
        Ok(())
    }
}

fn capitalize_first(input: &str) -> String {
    let mut chars = input.chars();
    let head = chars.next().into_iter().flat_map(char::to_uppercase);
    let tail = chars.flat_map(char::to_lowercase);
    head.chain(tail).collect()
}

#[cfg(test)]
mod test {
    use crate::{
        concat_with_newline,
        test_helpers::{
            self, expected_cert_plaintext_display, expected_cert_request_plaintext_display,
            BreakableSignature,
        },
        Description, Exemption, FormatMethod, Formattable, Infrastructure, Issued,
        IssuerAdditionalFields, KeyPair, Manufacturer, RequestBuilder,
    };

    #[test]
    fn plaintext_display_for_root_exemption_certificate_matches_expected_display() {
        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let public_key = cert.public_key();

        let expected_text = expected_cert_plaintext_display(
            &cert,
            "Root",
            "Exemption",
            &format!("(public key: {public_key})"),
            &format!("(public key: {public_key})"),
            None,
            None,
        );
        let text = cert.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_intermediate_infrastructure_certificate_matches_expected_display() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let req =
            RequestBuilder::intermediate_v1_builder(KeyPair::new_random().public_key()).build();
        let int_cert = root_cert
            .issue_cert(req, IssuerAdditionalFields::default())
            .unwrap();

        let expected_text = expected_cert_plaintext_display(
            &int_cert,
            "Intermediate",
            "Infrastructure",
            &format!("(public key: {})", int_cert.public_key()),
            &format!("(public key: {})", root_cert.public_key()),
            None,
            None,
        );
        let text = int_cert.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_leaf_manufacturer_certificate_matches_expected_display() {
        let leaf_cert = test_helpers::create_leaf_cert::<Manufacturer>();
        let leaf_public_key = leaf_cert.public_key();
        let issuer_public_key = leaf_cert.issuer_public_key();

        let expected_text = expected_cert_plaintext_display(
            &leaf_cert,
            "Leaf",
            "Manufacturer",
            &format!("(public key: {leaf_public_key})"),
            &format!("(public key: {issuer_public_key})"),
            None,
            None,
        );
        let text = leaf_cert.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_intermediate_certificate_with_description_matches_expected_display() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .with_description(
                Description::default()
                    .with_name("A Person")
                    .with_email("a.p@example.com"),
            )
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let req = RequestBuilder::intermediate_v1_builder(KeyPair::new_random().public_key())
            .with_description(Description::default().with_name("B Person"))
            .build();
        let intermediate_cert = root_cert
            .issue_cert(req, IssuerAdditionalFields::default())
            .unwrap();

        let int_public_key = intermediate_cert.public_key();

        let expected_text = expected_cert_plaintext_display(
            &intermediate_cert,
            "Intermediate",
            "Exemption",
            &format!("B Person (public key: {})", int_public_key),
            &format!(
                "A Person, a.p@example.com (public key: {})",
                root_cert.public_key()
            ),
            None,
            None,
        );
        let text = intermediate_cert
            .format(&FormatMethod::PlainDigest)
            .unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_certificate_with_emails_to_notify_matches_expected_display() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_public_key = int_kp.public_key();

        let intermediate_req = RequestBuilder::intermediate_v1_builder(int_kp.public_key()).build();
        let intermediate_cert = root_cert
            .issue_cert(intermediate_req, IssuerAdditionalFields::default())
            .unwrap();

        let leaf_req = RequestBuilder::leaf_v1_builder(KeyPair::new_random().public_key())
            .with_emails_to_notify(vec!["a@example.com", "b@example.com"])
            .build();
        let leaf_cert = intermediate_cert
            .load_key(int_kp)
            .unwrap()
            .issue_cert(
                leaf_req,
                IssuerAdditionalFields::default().with_emails_to_notify(vec!["c@example.com"]),
            )
            .unwrap();

        let leaf_public_key = leaf_cert.public_key();

        let expected_text = expected_cert_plaintext_display(
            &leaf_cert,
            "Leaf",
            "Exemption",
            &format!("(public key: {leaf_public_key})"),
            &format!("(public key: {int_public_key})"),
            Some(concat_with_newline!(
                "  Emails to notify:",
                "    a@example.com",
                "    b@example.com",
                "    c@example.com",
            )),
            None,
        );
        let text = leaf_cert.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_certificate_with_orchid_id_matches_expected_display() {
        let kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .with_description(Description::default().with_orcid("0000-0002-1825-0097"))
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let public_key = root_cert.public_key();

        let expected_text = expected_cert_plaintext_display(
            &root_cert,
            "Root",
            "Exemption",
            &format!("0000-0002-1825-0097 (public key: {public_key})"),
            &format!("0000-0002-1825-0097 (public key: {public_key})"),
            None,
            None,
        );
        let text = root_cert.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_root_manufacturer_certificate_with_invalid_signature_matches_expected_display(
    ) {
        let kp = KeyPair::new_random();
        let mut cert = RequestBuilder::<Manufacturer>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        cert.break_signature();
        let public_key = cert.public_key();

        let expected_text = expected_cert_plaintext_display(
            &cert,
            "Root",
            "Manufacturer",
            &format!("(public key: {public_key})"),
            &format!("(public key: {public_key})"),
            None,
            Some(concat_with_newline!(
                "",
                "INVALID: The signature failed verification"
            )),
        );
        let text = cert.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_root_infrastructure_certificate_request_matches_expected_display() {
        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key()).build();

        let public_key = req.public_key();

        let expected_text = expected_cert_request_plaintext_display(
            &req,
            "Root",
            "Infrastructure",
            &format!("(public key: {public_key})"),
            None,
        );
        let text = req.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_intermediate_exemption_certificate_request_matches_expected_display() {
        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Exemption>::intermediate_v1_builder(kp.public_key()).build();

        let public_key = req.public_key();

        let expected_text = expected_cert_request_plaintext_display(
            &req,
            "Intermediate",
            "Exemption",
            &format!("(public key: {public_key})"),
            None,
        );
        let text = req.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_leaf_manufacturer_certificate_request_matches_expected_display() {
        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Manufacturer>::leaf_v1_builder(kp.public_key()).build();

        let public_key = req.public_key();

        let expected_text = expected_cert_request_plaintext_display(
            &req,
            "Leaf",
            "Manufacturer",
            &format!("(public key: {public_key})"),
            None,
        );
        let text = req.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }

    #[test]
    fn plaintext_display_for_certificate_request_with_description_matches_expected_display() {
        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Manufacturer>::leaf_v1_builder(kp.public_key())
            .with_description(
                Description::default()
                    .with_name("A Person")
                    .with_email("a.p@gmail.com")
                    .with_orcid("0000-0002-1825-0097"),
            )
            .build();

        let public_key = req.public_key();

        let expected_text = expected_cert_request_plaintext_display(
            &req,
            "Leaf",
            "Manufacturer",
            &format!("A Person, a.p@gmail.com, 0000-0002-1825-0097 (public key: {public_key})"),
            None,
        );
        let text = req.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(text, expected_text)
    }
}
