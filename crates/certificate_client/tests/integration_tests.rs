// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Tests of expected behaviour when CLI args are incorrect/missing, faketime tests.
#[cfg(all(test, unix))]
mod tests {

    use std::process::Command;

    use assert_cmd::prelude::CommandCargoExt;

    use rexpect::session::spawn_command;
    use tempfile::TempDir;

    use certificates::test_helpers::{expected_cert_display, expected_cert_request_display};
    use certificates::{
        concat_with_newline, Builder, CertificateBundle, DatabaseTokenGroup, Digestible, Exemption,
        ExpirationError, HierarchyKindParseError, Infrastructure, Issued, IssuerAdditionalFields,
        KeyPair, Manufacturer, RequestBuilder, RoleKindParseError,
    };

    use certificate_client::inspect::NO_PATH_FOUND_TEXT;
    use certificate_client::passphrase_reader::{
        CREATE_CERT_PASSPHRASE_PROMPT, CREATE_PASSPHRASE_REENTRY_PROMPT, ENTER_PASSPHRASE_PROMPT,
    };
    use certificates::file::{
        load_cert_request_from_file, load_certificate_bundle_from_file,
        load_token_request_from_file, save_cert_request_to_file, save_certificate_bundle_to_file,
        save_keypair_to_file, save_public_key_to_file,
    };

    #[test]
    fn error_on_creating_request_if_cert_type_not_provided() {
        let command = Command::cargo_bin("sdna-create-cert").unwrap();

        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();

        assert!(output.contains("error"))
    }

    #[test]
    fn error_on_creating_request_using_non_parsable_cert_role() {
        let mut command = Command::cargo_bin("sdna-create-cert").unwrap();
        command.args(["non-existent-role"]);
        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();
        let expected_error = RoleKindParseError.to_string();
        assert!(output.contains(&expected_error))
    }

    #[test]
    fn error_on_creating_request_using_non_parsable_cert_hierarchy() {
        let mut command = Command::cargo_bin("sdna-create-cert").unwrap();
        command.args(["exemption"]);
        command.args(["non-existent-hierarchy"]);
        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();
        let expected_error = HierarchyKindParseError.to_string();
        assert!(output.contains(&expected_error))
    }

    #[test]
    fn can_create_cert_request_with_public_key_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.certr");
        let pub_key_path = temp_dir.path().join("1234.pub");

        let kp = KeyPair::new_random();
        save_public_key_to_file(kp.public_key(), &pub_key_path).unwrap();

        let mut command = Command::cargo_bin("sdna-create-cert").unwrap();
        command.args(["exemption"]);
        command.args(["root"]);
        command.args(["--output", request_path.to_str().unwrap()]);
        command.args(["--key-from-file", pub_key_path.to_str().unwrap()]);

        command.output().unwrap();

        let request = load_cert_request_from_file::<Exemption>(&request_path)
            .expect("should have been able to load request");
        assert_eq!(request.public_key(), &kp.public_key())
    }

    #[test]
    fn can_create_cert_request_with_public_key_from_hex() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.certr");

        let kp = KeyPair::new_random();
        let hex = kp.public_key().to_string();

        let mut command = Command::cargo_bin("sdna-create-cert").unwrap();
        command.args(["exemption"]);
        command.args(["root"]);
        command.args(["--output", request_path.to_str().unwrap()]);
        command.args(["--key-from-hex", &hex]);

        command.output().unwrap();

        let request = load_cert_request_from_file::<Exemption>(&request_path)
            .expect("should have been able to load request");
        assert_eq!(request.public_key(), &kp.public_key())
    }

    #[test]
    fn can_create_token_request_with_public_key_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.dtr");
        let pub_key_path = temp_dir.path().join("1234.pub");

        let kp = KeyPair::new_random();
        save_public_key_to_file(kp.public_key(), &pub_key_path).unwrap();

        let mut command = Command::cargo_bin("sdna-create-token").unwrap();
        command.args(["--output", request_path.to_str().unwrap()]);
        command.args(["--key-from-file", pub_key_path.to_str().unwrap()]);
        command.args(["database"]);

        command.output().unwrap();

        let request = load_token_request_from_file::<DatabaseTokenGroup>(&request_path)
            .expect("should have been able to load token request");
        assert_eq!(request.public_key(), &kp.public_key())
    }

    #[test]
    fn can_create_token_request_with_public_key_from_hex() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.dtr");

        let kp = KeyPair::new_random();
        let hex = kp.public_key().to_string();

        let mut command = Command::cargo_bin("sdna-create-token").unwrap();
        command.args(["--output", request_path.to_str().unwrap()]);
        command.args(["--key-from-hex", &hex]);
        command.args(["database"]);

        command.output().unwrap();

        let request = load_token_request_from_file::<DatabaseTokenGroup>(&request_path)
            .expect("should have been able to load token request");
        assert_eq!(request.public_key(), &kp.public_key())
    }

    #[test]
    fn plaintext_digest_of_request_contains_only_expected_lines() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.certr");
        let key_path = temp_dir.path().join("1234.priv");

        let mut command = Command::cargo_bin("sdna-create-cert").unwrap();
        command.args(["exemption"]);
        command.args(["root"]);
        command.args(["--output", request_path.to_str().unwrap()]);
        command.args(["--create-new-key", key_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        p.exp_string(CREATE_CERT_PASSPHRASE_PROMPT).unwrap();
        p.send_line("1234").unwrap();
        p.exp_string(CREATE_PASSPHRASE_REENTRY_PROMPT).unwrap();
        p.send_line("1234").unwrap();
        p.exp_eof().unwrap();

        assert!(request_path.exists());
        assert!(key_path.exists());

        // Now retrieve plaintext digest
        let mut command = Command::cargo_bin("sdna-inspect-cert").unwrap();
        command.args(["exemption"]);
        command.args(["request", request_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        let plaintext_output = p.exp_eof().unwrap();

        let req = load_cert_request_from_file::<Exemption>(&request_path).unwrap();
        let expected_text = expected_cert_request_display(
            &req,
            "Root",
            "Exemption",
            &format!("(public key: {})", req.public_key()),
            None,
        ) + "\n";

        assert_eq!(
            normalize_newlines(&plaintext_output),
            normalize_newlines(&expected_text)
        )
    }

    #[test]
    fn leaf_request_display_and_certificate_display_show_correct_emails_to_notify() {
        let root_kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_bundle = CertificateBundle::new(root_cert, None);

        let int_kp = KeyPair::new_random();
        let intermediate_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let temp_dir = TempDir::new().unwrap();
        let int_cert_path = temp_dir.path().join("int.cert");
        let int_key_path = temp_dir.path().join("int.priv");

        let int_bundle = root_bundle
            .issue_cert_bundle(intermediate_req, IssuerAdditionalFields::default(), root_kp)
            .expect("Couldn't issue cert bundle");

        // Save intermediate cert and its key to file so we can use it in CLI
        save_certificate_bundle_to_file(int_bundle, &int_cert_path).unwrap();
        save_keypair_to_file(int_kp, "1234", &int_key_path).unwrap();

        // Create leaf cert via CLI
        let leaf_request_path = temp_dir.path().join("leaf.certr");
        let leaf_key_path = temp_dir.path().join("leaf.priv");

        let mut command = Command::cargo_bin("sdna-create-cert").unwrap();
        command.args(["exemption"]);
        command.args(["leaf"]);
        command.args(["--output", leaf_request_path.to_str().unwrap()]);
        command.args(["--notify", "a@example.com"]);
        command.args(["--notify", "b@example.com"]);
        command.args(["--create-new-key", leaf_key_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        p.exp_string(CREATE_CERT_PASSPHRASE_PROMPT).unwrap();
        p.send_line("1234").unwrap();
        p.exp_string(CREATE_PASSPHRASE_REENTRY_PROMPT).unwrap();
        p.send_line("1234").unwrap();

        p.exp_eof().unwrap();

        assert!(leaf_request_path.exists());

        let mut command = Command::cargo_bin("sdna-inspect-cert").unwrap();
        command.args(["exemption"]);
        command.args(["request", leaf_request_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        let plaintext_output = p.exp_eof().unwrap();

        let leaf_request = load_cert_request_from_file::<Exemption>(&leaf_request_path).unwrap();
        let expected_text = expected_cert_request_display(
            &leaf_request,
            "Leaf",
            "Exemption",
            &format!("(public key: {})", leaf_request.public_key()),
            Some(concat_with_newline!(
                "  Emails to notify:",
                "    a@example.com",
                "    b@example.com",
            )),
        ) + "\n";

        assert_eq!(
            normalize_newlines(&plaintext_output),
            normalize_newlines(&expected_text)
        );

        let leaf_cert_path = temp_dir.path().join("leaf.cert");

        let mut command = Command::cargo_bin("sdna-sign-cert").unwrap();
        command.args(["exemption"]);
        command.args(["sign"]);
        command.args([leaf_request_path.to_str().unwrap()]);
        command.args([int_cert_path.to_str().unwrap()]);
        command.args(["--key", int_key_path.to_str().unwrap()]);
        command.args(["--output", leaf_cert_path.to_str().unwrap()]);
        command.args(["--notify", "b@example.com"]);
        command.args(["--notify", "c@example.com"]);

        let mut p = spawn_command(command, None).unwrap();
        p.exp_string(ENTER_PASSPHRASE_PROMPT).unwrap();
        p.send_line("1234").unwrap();
        p.exp_eof().unwrap();

        assert!(leaf_cert_path.exists());

        // Now retrieve plaintext digest of leaf cert
        let mut command = Command::cargo_bin("sdna-inspect-cert").unwrap();
        command.args(["exemption"]);
        command.args(["cert", leaf_cert_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        let plaintext_output = p.exp_eof().unwrap();

        let cert = load_certificate_bundle_from_file::<Exemption>(&leaf_cert_path)
            .unwrap()
            .get_lead_cert()
            .unwrap()
            .clone();

        let leaf_public_key = cert.public_key();
        let int_public_key = cert.issuer_public_key();

        let expected_text = expected_cert_display(
            &cert,
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
        ) + "\n";
        assert_eq!(
            normalize_newlines(&plaintext_output),
            normalize_newlines(&expected_text)
        )
    }

    #[test]
    fn plaintext_digest_of_certificate_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("root.cert");

        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        save_certificate_bundle_to_file(CertificateBundle::new(cert.clone(), None), &cert_path)
            .unwrap();

        // Now retrieve plaintext digest
        let mut command = Command::cargo_bin("sdna-inspect-cert").unwrap();
        command.args(["infrastructure"]);
        command.args(["cert", cert_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        let plaintext_output = p.exp_eof().unwrap();

        let public_key = cert.public_key();

        let expected_text = expected_cert_display(
            &cert,
            "Root",
            "Infrastructure",
            &format!("(public key: {public_key})"),
            &format!("(public key: {public_key})"),
            None,
        ) + "\n";
        assert_eq!(
            normalize_newlines(&plaintext_output),
            normalize_newlines(&expected_text)
        )
    }

    #[test]
    fn cannot_sign_without_providing_certificate_path() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("1234.certr");
        let key_path = temp_dir.path().join("1234.priv");

        let mut command = Command::cargo_bin("sdna-create-cert").unwrap();
        command.args(["manufacturer"]);
        command.args(["root"]);
        command.args(["--output", request_path.to_str().unwrap()]);
        command.args(["--create-new-key", key_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        p.exp_string(CREATE_CERT_PASSPHRASE_PROMPT).unwrap();
        p.send_line("1234").unwrap();
        p.exp_string(CREATE_PASSPHRASE_REENTRY_PROMPT).unwrap();
        p.send_line("1234").unwrap();
        p.exp_eof().unwrap();

        assert!(request_path.exists());
        assert!(key_path.exists());

        let cert_path = temp_dir.path().join("1234.cert");

        let mut command = Command::cargo_bin("sdna-sign-cert").unwrap();
        command.args(["manufacturer"]);
        command.args(["sign"]);
        command.args([request_path.to_str().unwrap()]);
        command.args(["--key", key_path.to_str().unwrap()]);
        command.args(["--output", cert_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();
        assert!(output.contains("error"));
    }

    #[test]
    fn cannot_set_negative_value_for_days_valid() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("root.certr");
        let cert_path = temp_path.join("root.cert");
        let key_path = temp_path.join("root.priv");

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, "passphrase", &key_path).unwrap();

        let mut command = Command::cargo_bin("sdna-sign-cert").unwrap();
        command.args(["exemption"]);
        command.args(["self-sign"]);
        command.args([request_path.to_str().unwrap()]);
        command.args(["--key", key_path.to_str().unwrap()]);
        command.args(["--output", cert_path.to_str().unwrap()]);
        command.args(["--days-valid=-1"]);

        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();
        assert!(!cert_path.exists());
        assert!(output.contains(&ExpirationError::InsufficientDaysValid.to_string()))
    }

    #[test]
    fn cannot_set_zero_value_for_days_valid() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("root.certr");
        let cert_path = temp_dir.path().join("root.cert");
        let key_path = temp_dir.path().join("root.priv");

        let kp = KeyPair::new_random();
        let req = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key()).build();

        save_cert_request_to_file(req, &request_path).unwrap();
        save_keypair_to_file(kp, "passphrase", &key_path).unwrap();

        assert!(request_path.exists());
        assert!(key_path.exists());

        let mut command = Command::cargo_bin("sdna-sign-cert").unwrap();
        command.args(["exemption"]);
        command.args(["self-sign"]);
        command.args([request_path.to_str().unwrap()]);
        command.args(["--key", key_path.to_str().unwrap()]);
        command.args(["--output", cert_path.to_str().unwrap()]);
        command.args(["--days-valid", "0"]);

        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();

        assert!(!cert_path.exists());

        assert!(output.contains(&ExpirationError::InsufficientDaysValid.to_string()))
    }

    #[test]
    fn certificate_digest_reports_certificate_not_yet_valid() {
        check_faketime_installed().expect("This test requires faketime");

        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("root.cert");

        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Infrastructure>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        save_certificate_bundle_to_file(CertificateBundle::new(cert.clone(), None), &cert_path)
            .unwrap();

        let mut command = Command::new("faketime");
        command.arg("-3day");
        command.arg("../../target/debug/sdna-inspect-cert");
        command.args(["infrastructure"]);
        command.args(["cert", cert_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        let plaintext_output = p.exp_eof().unwrap();

        let mut expected_text = expected_cert_display(
            &cert,
            "Root",
            "Infrastructure",
            &format!("(public key: {})", cert.public_key()),
            &format!("(public key: {})", cert.public_key()),
            None,
        );
        expected_text.push_str("\nINVALID: Not yet valid\n");

        assert_eq!(
            normalize_newlines(&plaintext_output),
            normalize_newlines(&expected_text)
        )
    }

    #[test]
    fn certificate_digest_reports_certificate_expired_after_expiration_date_has_passed() {
        check_faketime_installed().expect("This test requires faketime");

        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("root.cert");

        let kp = KeyPair::new_random();
        let cert = RequestBuilder::<Manufacturer>::root_v1_builder(kp.public_key())
            .build()
            .load_key(kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();

        save_certificate_bundle_to_file(CertificateBundle::new(cert.clone(), None), &cert_path)
            .unwrap();

        let mut command = Command::new("faketime");
        command.arg("+29day");

        command.arg("../../target/debug/sdna-inspect-cert");
        command.args(["manufacturer"]);
        command.args(["cert", cert_path.to_str().unwrap()]);

        let mut p = spawn_command(command, None).unwrap();
        let plaintext_output = p.exp_eof().unwrap();

        let mut expected_text = expected_cert_display(
            &cert,
            "Root",
            "Manufacturer",
            &format!("(public key: {})", cert.public_key()),
            &format!("(public key: {})", cert.public_key()),
            None,
        );
        expected_text.push_str("\nINVALID: Expired\n");

        assert_eq!(
            normalize_newlines(&plaintext_output),
            normalize_newlines(&expected_text)
        )
    }

    #[test]
    fn no_path_to_root_found_when_intermediate_has_expired() {
        check_faketime_installed().expect("This test requires faketime");

        let root_kp = KeyPair::new_random();
        let root_pk = root_kp.public_key();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_bundle = CertificateBundle::new(root_cert, None);

        let int_kp = KeyPair::new_random();
        let intermediate_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        // Create intermediate cert that expires in two days
        let int_bundle = root_bundle
            .issue_cert_bundle(
                intermediate_req,
                IssuerAdditionalFields::default()
                    .with_expiry_in_days(2)
                    .unwrap(),
                root_kp.clone(),
            )
            .expect("Couldn't issue cert bundle");

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_req, IssuerAdditionalFields::default(), int_kp)
            .expect("Could not sign leaf cert");

        let temp_dir = TempDir::new().unwrap();

        let leaf_cert_path = temp_dir.path().join("1234.cert");

        save_certificate_bundle_to_file(leaf_bundle, &leaf_cert_path).unwrap();

        let mut command = Command::new("faketime");
        command.arg("+3day");
        command.arg("../../target/debug/sdna-inspect-cert");
        command.arg("exemption");
        command.args([
            "chain",
            leaf_cert_path.to_str().unwrap(),
            "all-paths",
            &root_pk.to_string(),
        ]);

        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();
        assert!(output.contains(NO_PATH_FOUND_TEXT));
    }

    #[test]
    fn no_path_to_root_found_when_leaf_has_expired() {
        check_faketime_installed().expect("This test requires faketime");

        let root_kp = KeyPair::new_random();
        let root_pk = root_kp.public_key();

        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_bundle = CertificateBundle::new(root_cert, None);

        let int_kp = KeyPair::new_random();
        let intermediate_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let int_bundle = root_bundle
            .issue_cert_bundle(intermediate_req, IssuerAdditionalFields::default(), root_kp)
            .expect("Couldn't issue cert bundle");

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        // Create leaf cert that expires in two days
        let leaf_bundle = int_bundle
            .issue_cert_bundle(
                leaf_req,
                IssuerAdditionalFields::default()
                    .with_expiry_in_days(2)
                    .unwrap(),
                int_kp,
            )
            .expect("Could not sign leaf cert");

        let temp_dir = TempDir::new().unwrap();

        let leaf_cert_path = temp_dir.path().join("1234.cert");

        save_certificate_bundle_to_file(leaf_bundle, &leaf_cert_path).unwrap();

        let mut command = Command::new("faketime");
        command.arg("+3day");
        command.arg("../../target/debug/sdna-inspect-cert");
        command.arg("exemption");
        command.args([
            "chain",
            leaf_cert_path.to_str().unwrap(),
            "all-paths",
            &root_pk.to_string(),
        ]);

        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();
        assert!(output.contains(NO_PATH_FOUND_TEXT));
    }

    #[test]
    fn single_path_to_root_found_when_second_intermediate_has_expired() {
        let root_kp_a = KeyPair::new_random();
        let root_pk_a = root_kp_a.public_key();

        let root_cert_a = RequestBuilder::<Exemption>::root_v1_builder(root_kp_a.public_key())
            .build()
            .load_key(root_kp_a.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_bundle_a = CertificateBundle::new(root_cert_a, None);

        let root_kp_b = KeyPair::new_random();
        let root_pk_b = root_kp_b.public_key();

        let root_cert_b = RequestBuilder::<Exemption>::root_v1_builder(root_kp_b.public_key())
            .build()
            .load_key(root_kp_b.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_bundle_b = CertificateBundle::new(root_cert_b, None);

        let int_kp = KeyPair::new_random();
        let int_req_a =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let int_req_b = int_req_a.clone();

        let int_bundle_a = root_bundle_a
            .issue_cert_bundle(int_req_a, IssuerAdditionalFields::default(), root_kp_a)
            .expect("Couldn't issue cert bundle");

        let int_bundle_b = root_bundle_b
            .issue_cert_bundle(
                int_req_b,
                IssuerAdditionalFields::default()
                    .with_expiry_in_days(2)
                    .unwrap(),
                root_kp_b,
            )
            .expect("Couldn't issue cert");

        let int_bundle = int_bundle_a
            .merge(int_bundle_b)
            .expect("Could not merge cert bundles");

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_req, IssuerAdditionalFields::default(), int_kp)
            .expect("Could not sign leaf cert");

        let temp_dir = TempDir::new().unwrap();

        let leaf_cert_path = temp_dir.path().join("1234.cert");

        save_certificate_bundle_to_file(leaf_bundle, &leaf_cert_path).unwrap();

        let mut command = Command::new("faketime");
        command.arg("+3day");
        command.arg("../../target/debug/sdna-inspect-cert");
        command.arg("exemption");
        command.args([
            "chain",
            leaf_cert_path.to_str().unwrap(),
            "all-paths",
            &root_pk_a.to_string(),
            &root_pk_b.to_string(),
        ]);

        let mut p = spawn_command(command, None).unwrap();
        let output = p.exp_eof().unwrap();
        assert!(output.contains("Path 1"));
        assert!(!output.contains("Path 2"));
    }

    #[test]
    fn expired_intermediate_is_found_when_viewing_certs_not_part_of_path() {
        let root_kp_a = KeyPair::new_random();
        let root_pk_a = root_kp_a.public_key();

        let root_cert_a = RequestBuilder::<Exemption>::root_v1_builder(root_kp_a.public_key())
            .build()
            .load_key(root_kp_a.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_bundle_a = CertificateBundle::new(root_cert_a, None);

        let root_kp_b = KeyPair::new_random();
        let root_pk_b = root_kp_b.public_key();

        let root_cert_b = RequestBuilder::<Exemption>::root_v1_builder(root_kp_b.public_key())
            .build()
            .load_key(root_kp_b.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .expect("Couldn't sign");

        let root_bundle_b = CertificateBundle::new(root_cert_b, None);

        let int_kp = KeyPair::new_random();
        let int_req_a =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let int_req_b = int_req_a.clone();

        let int_bundle_a = root_bundle_a
            .issue_cert_bundle(int_req_a, IssuerAdditionalFields::default(), root_kp_a)
            .expect("Couldn't issue cert bundle");

        let int_bundle_b = root_bundle_b
            .issue_cert_bundle(
                int_req_b,
                IssuerAdditionalFields::default()
                    .with_expiry_in_days(2)
                    .unwrap(),
                root_kp_b,
            )
            .expect("Couldn't issue cert");
        let int_cert_b = int_bundle_b.certs[0].clone();

        let int_bundle = int_bundle_a
            .merge(int_bundle_b)
            .expect("Could not merge cert bundles");

        let leaf_kp = KeyPair::new_random();
        let leaf_req = RequestBuilder::<Exemption>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_req, IssuerAdditionalFields::default(), int_kp)
            .expect("Could not sign leaf cert");

        let temp_dir = TempDir::new().unwrap();

        let leaf_cert_path = temp_dir.path().join("1234.cert");

        save_certificate_bundle_to_file(leaf_bundle, &leaf_cert_path).unwrap();

        let mut command = Command::new("faketime");
        command.arg("+3day");
        command.arg("../../target/debug/sdna-inspect-cert");
        command.arg("exemption");
        command.args([
            "chain",
            leaf_cert_path.to_str().unwrap(),
            "not-part-of-path",
            &root_pk_a.to_string(),
            &root_pk_b.to_string(),
        ]);

        let mut p = spawn_command(command, None).unwrap();
        let mut output = p.exp_eof().unwrap();
        output.retain(|c| !c.is_whitespace());

        let mut int_cert_b_display_text = int_cert_b.into_digest().to_string();
        int_cert_b_display_text.retain(|c| !c.is_whitespace());

        assert!(output.contains(&int_cert_b_display_text));
    }

    fn check_faketime_installed() -> Result<(), &'static str> {
        let output = Command::new("which")
            .arg("faketime")
            .output()
            .expect("Failed to execute command");

        if output.status.success() {
            Ok(())
        } else {
            Err("faketime not installed")
        }
    }

    fn normalize_newlines(s: &str) -> String {
        s.replace("\r\n", "\n")
    }
}
