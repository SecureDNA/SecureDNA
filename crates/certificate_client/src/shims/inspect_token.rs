// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for inspecting the contents of a certificate or certificate request

use std::{io::Write, path::PathBuf};

use clap::{crate_version, Parser, Subcommand};

use super::error::CertCliError;
use crate::common::ChainViewMode;
use certificates::{
    file::{load_token_bundle_from_file, load_token_request_from_file, TokenExtension},
    DatabaseTokenGroup, ExemptionListTokenGroup, FormatMethod, Formattable, HltTokenGroup,
    KeyserverTokenGroup, SynthesizerTokenGroup, TokenGroup, TokenKind,
};

#[derive(Debug, Parser)]
#[clap(
    name = "sdna-inspect-token",
    about = "Inspects and validates a SecureDNA token, token request, or a token's certificate chain",
    version = crate_version!()
)]

pub struct InspectTokenOpts {
    #[clap(
        help = "Type of token [possible values: keyserver, exemption-list, database, synthesizer, hlt]"
    )]
    pub token: TokenKind,
    #[clap(subcommand)]
    pub target: Target,
    #[clap(
        global = true,
        long,
        help = "How to display results [default: plain-digest] [possible values: plain-digest, json-digest, json-full]",
        default_value = "plain-digest"
    )]
    pub format: FormatMethod,
}
/// The data type being inspected
#[derive(Debug, Subcommand)]
pub enum Target {
    /// Inspect a token request
    ///
    Request {
        #[clap(help = "Path of token request to be inspected")]
        file: PathBuf,
    },
    /// Inspect a token
    Token {
        #[clap(help = "Path of token with chain to be inspected")]
        file: PathBuf,
    },
    // Inspect a token chain
    Chain {
        #[clap(help = "Path of token with chain to be inspected")]
        file: PathBuf,
        #[clap(subcommand)]
        view_mode: ChainViewMode,
    },
}

pub fn main<W: Write, E: Write>(
    opts: &InspectTokenOpts,
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

fn run(opts: &InspectTokenOpts) -> Result<String, CertCliError> {
    match opts.token {
        TokenKind::ExemptionList => inspect_file::<ExemptionListTokenGroup>(opts),
        TokenKind::Keyserver => inspect_file::<KeyserverTokenGroup>(opts),
        TokenKind::Database => inspect_file::<DatabaseTokenGroup>(opts),
        TokenKind::Hlt => inspect_file::<HltTokenGroup>(opts),
        TokenKind::Synthesizer => inspect_file::<SynthesizerTokenGroup>(opts),
    }
}

fn inspect_file<T: TokenGroup + TokenExtension>(
    opts: &InspectTokenOpts,
) -> Result<String, CertCliError> {
    let format_method = &opts.format;

    let display_text = match &opts.target {
        Target::Request { file } => {
            let file = match file.extension() {
                Some(_) => file.to_owned(),
                None => file.with_extension(T::REQUEST_EXT),
            };
            let request = load_token_request_from_file::<T>(&file)?;
            request.format(format_method).map_err(CertCliError::from)
        }
        Target::Token { file } => {
            let file = match file.extension() {
                Some(_) => file.to_owned(),
                None => file.with_extension(T::TOKEN_EXT),
            };
            let token_bundle = load_token_bundle_from_file::<T>(&file)?;
            token_bundle
                .token
                .format(format_method)
                .map_err(CertCliError::from)
        }
        Target::Chain { file, view_mode } => {
            let file = match file.extension() {
                Some(_) => file.to_owned(),
                None => file.with_extension(T::TOKEN_EXT),
            };
            let token_bundle = load_token_bundle_from_file::<T>(&file)?;
            view_mode.display_chain(token_bundle, format_method)
        }
    }?;

    Ok(display_text)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use certificates::file::{
        save_token_bundle_to_file, save_token_request_to_file, FileError, TokenExtension,
    };
    use certificates::test_helpers::{create_leaf_bundle, create_leaf_cert};
    use certificates::{
        concat_with_newline,
        test_helpers::{
            create_database_token_bundle, create_hlt_token_bundle, create_intermediate_bundle,
            create_keyserver_token_bundle, create_synthesizer_token_bundle,
            expected_database_token_plaintext_display, expected_hlt_token_plaintext_display,
            expected_keyserver_token_plaintext_display,
            expected_synthesizer_token_plaintext_display, BreakableSignature,
        },
        Builder, CertificateBundle, DatabaseTokenGroup, DatabaseTokenRequest, Expiration,
        FormatMethod, Formattable, Infrastructure, Issued, IssuerAdditionalFields, KeyPair,
        KeyserverTokenGroup, KeyserverTokenRequest, RequestBuilder, TokenBundle, TokenKind,
    };
    use doprf::party::KeyserverId;

    use super::{run, InspectTokenOpts, Target};
    use crate::common::{ChainViewMode, NO_EXCLUDED_CERTS_TEXT, NO_PATH_FOUND_TEXT};
    use crate::shims::{error::CertCliError, inspect_token};

    #[test]
    fn inspect_plaintext_display_for_database_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.dt");

        let (token_bundle, _) = create_database_token_bundle();
        let expected_text = expected_database_token_plaintext_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
            None,
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_database_token_warns_if_signature_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.dt");

        let (mut token_bundle, _) = create_database_token_bundle();
        token_bundle.token.break_signature();
        let expected_text = expected_database_token_plaintext_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
            Some(concat_with_newline!(
                "",
                "INVALID: The signature failed verification"
            )),
        );
        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_hlt_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.ht");

        let (token_bundle, _) = create_hlt_token_bundle();
        let expected_text = expected_hlt_token_plaintext_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
            None,
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Hlt,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_hlt_token_warns_if_signature_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.ht");

        let (mut token_bundle, _) = create_hlt_token_bundle();
        token_bundle.token.break_signature();
        let expected_text = expected_hlt_token_plaintext_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
            Some(concat_with_newline!(
                "",
                "INVALID: The signature failed verification"
            )),
        );
        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Hlt,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_keyserver_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.kt");

        let (token_bundle, _) = create_keyserver_token_bundle();
        let expected_text = expected_keyserver_token_plaintext_display(
            &token_bundle.token,
            "1",
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
            None,
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_keyserver_token_warns_if_signature_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.kt");

        let (mut token_bundle, _) = create_keyserver_token_bundle();
        token_bundle.token.break_signature();
        let expected_text = expected_keyserver_token_plaintext_display(
            &token_bundle.token,
            "1",
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
            Some(concat_with_newline!(
                "",
                "INVALID: The signature failed verification"
            )),
        );
        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_synthesizer_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.st");

        let (token_bundle, _) = create_synthesizer_token_bundle();

        let expected_text = expected_synthesizer_token_plaintext_display(
            &token_bundle.token,
            "maker.synth",
            "XL",
            "10AK",
            "10000 base pairs per day",
            None,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
            None,
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Synthesizer,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_synthesizer_token_warns_if_signature_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.st");

        let (mut token_bundle, _) = create_synthesizer_token_bundle();
        token_bundle.token.break_signature();
        let expected_text = expected_synthesizer_token_plaintext_display(
            &token_bundle.token,
            "maker.synth",
            "XL",
            "10AK",
            "10000 base pairs per day",
            None,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
            Some(concat_with_newline!(
                "",
                "INVALID: The signature failed verification"
            )),
        );
        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Synthesizer,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspecting_incorrect_token_type_fails_gracefully() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.st");

        let (token_bundle, _) = create_synthesizer_token_bundle();

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
        };
        let error = run(&opts)
            .expect_err("should not be able to inspect synthesizer token as keyserver token");
        assert!(matches!(
            error,
            CertCliError::FileError(FileError::UnexpectedFileExtension(_, _))
        ));
    }

    #[test]
    fn inspect_correctly_shows_all_certificates_in_token_chain() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.dt");

        let (int_bundle, int_kp, _) = create_intermediate_bundle::<Infrastructure>();

        let leaf_kp = KeyPair::new_random();
        let leaf_req =
            RequestBuilder::<Infrastructure>::leaf_v1_builder(leaf_kp.public_key()).build();

        let int_cert = int_bundle.get_lead_cert().unwrap().to_owned();

        let leaf_cert = int_cert
            .clone()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .unwrap();

        let chain = int_bundle.issue_chain();
        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let token_kp = KeyPair::new_random();
        let token_request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());

        let token = leaf_bundle
            .get_lead_cert()
            .unwrap()
            .clone()
            .load_key(leaf_kp)
            .unwrap()
            .issue_database_token(token_request, Expiration::default())
            .unwrap();

        let chain = leaf_bundle.issue_chain();

        let token_bundle = TokenBundle::<DatabaseTokenGroup>::new(token, chain);

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Chain {
                file: token_path,
                view_mode: ChainViewMode::AllCerts,
            },
            format: FormatMethod::PlainDigest,
        };

        let result = run(&opts).unwrap();

        // check 'AllCerts' contains leaf cert and int cert
        let int_cert_display = int_cert.format(&FormatMethod::PlainDigest).unwrap();
        let leaf_cert_display = leaf_cert.format(&FormatMethod::PlainDigest).unwrap();

        assert!(result.contains(&int_cert_display));
        assert!(result.contains(&leaf_cert_display));
    }

    #[test]
    fn inspect_correctly_shows_path_to_issuer_of_token_chain() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.dt");

        let (int_bundle, int_kp, root_public_key) = create_intermediate_bundle::<Infrastructure>();

        let leaf_kp = KeyPair::new_random();
        let leaf_req =
            RequestBuilder::<Infrastructure>::leaf_v1_builder(leaf_kp.public_key()).build();

        let int_cert = int_bundle.get_lead_cert().unwrap().to_owned();

        let leaf_cert = int_cert
            .clone()
            .load_key(int_kp)
            .unwrap()
            .issue_cert(leaf_req, IssuerAdditionalFields::default())
            .unwrap();

        let chain = int_bundle.issue_chain();
        let leaf_bundle = CertificateBundle::new(leaf_cert.clone(), Some(chain));

        let token_kp = KeyPair::new_random();
        let token_request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());

        let token = leaf_bundle
            .get_lead_cert()
            .unwrap()
            .clone()
            .load_key(leaf_kp)
            .unwrap()
            .issue_database_token(token_request, Expiration::default())
            .unwrap();

        let chain = leaf_bundle.issue_chain();

        let token_bundle = TokenBundle::<DatabaseTokenGroup>::new(token.clone(), chain);

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Chain {
                file: token_path,
                view_mode: ChainViewMode::AllPaths {
                    public_keys: vec![root_public_key],
                },
            },
            format: FormatMethod::PlainDigest,
        };

        let result = run(&opts).unwrap();

        // check that path to issuer contains leaf cert and int cert
        let int_cert_display = int_cert.format(&FormatMethod::PlainDigest).unwrap();
        let leaf_cert_display = leaf_cert.format(&FormatMethod::PlainDigest).unwrap();
        let token_display = token.format(&FormatMethod::PlainDigest).unwrap();

        let mut expected_text = "Path 1:\n".to_owned();
        expected_text.push_str(&token_display);
        expected_text.push('\n');
        expected_text.push_str(&leaf_cert_display);
        expected_text.push('\n');
        expected_text.push_str(&int_cert_display);

        assert_eq!(result, expected_text);
    }

    #[test]
    fn inspect_correctly_identifies_redundant_certificates_in_token_chain() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.kt");

        let (leaf_bundle, leaf_kp, root_public_key) = create_leaf_bundle::<Infrastructure>();
        let token_request = KeyserverTokenRequest::v1_token_request(
            KeyPair::new_random().public_key(),
            KeyserverId::try_from(1).unwrap(),
        );
        let keyserver_token = leaf_bundle
            .get_lead_cert()
            .unwrap()
            .clone()
            .load_key(leaf_kp)
            .unwrap()
            .issue_keyserver_token(token_request, Expiration::default())
            .unwrap();
        let mut keyserver_chain = leaf_bundle.issue_chain();
        let extra_cert = create_leaf_cert().into_key_unavailable();
        keyserver_chain.add_item(extra_cert.clone());

        let token_bundle =
            TokenBundle::<KeyserverTokenGroup>::new(keyserver_token, keyserver_chain);

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Chain {
                file: token_path,
                view_mode: ChainViewMode::NotPartOfPath {
                    public_keys: vec![root_public_key],
                },
            },
            format: FormatMethod::PlainDigest,
        };

        let result = run(&opts).unwrap();

        let expected_text = extra_cert.format(&FormatMethod::PlainDigest).unwrap();
        assert_eq!(result, expected_text)
    }

    #[test]
    fn inspect_correctly_identifies_cases_where_no_path_to_issuer_exists() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.kt");

        let (token_bundle, _) = create_keyserver_token_bundle();

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();
        let incorrect_root_key = KeyPair::new_random().public_key();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Chain {
                file: token_path,
                view_mode: ChainViewMode::AllPaths {
                    public_keys: vec![incorrect_root_key],
                },
            },
            format: FormatMethod::PlainDigest,
        };

        let result = run(&opts).unwrap();
        assert_eq!(&result, NO_PATH_FOUND_TEXT)
    }

    #[test]
    fn inspect_identifies_cases_where_no_redundant_certificate_are_present() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.kt");

        let (token_bundle, root_public_key) = create_keyserver_token_bundle();

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Chain {
                file: token_path,
                view_mode: ChainViewMode::NotPartOfPath {
                    public_keys: vec![root_public_key],
                },
            },
            format: FormatMethod::PlainDigest,
        };

        let result = run(&opts).unwrap();
        assert_eq!(&result, NO_EXCLUDED_CERTS_TEXT)
    }

    #[test]
    fn inspect_request_infers_extension_if_not_provided() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("token");

        let kp = KeyPair::new_random();
        let request = DatabaseTokenRequest::v1_token_request(kp.public_key());
        save_token_request_to_file::<DatabaseTokenGroup>(
            request,
            &request_path.with_extension(DatabaseTokenGroup::REQUEST_EXT),
        )
        .unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Request { file: request_path },
            format: FormatMethod::PlainDigest,
        };

        inspect_token::run(&opts)
            .expect("inspect token tool should be able to infer request extension");
    }

    #[test]
    fn inspect_token_infers_extension_if_not_provided() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("token");

        let (token, _) = create_database_token_bundle();
        save_token_bundle_to_file::<DatabaseTokenGroup>(
            token,
            &request_path.with_extension(DatabaseTokenGroup::TOKEN_EXT),
        )
        .unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Token { file: request_path },
            format: FormatMethod::PlainDigest,
        };

        inspect_token::run(&opts)
            .expect("inspect token tool should be able to infer request extension");
    }
    #[test]
    fn inspect_token_chain_infers_extension_if_not_provided() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("token");

        let (token, _) = create_database_token_bundle();
        save_token_bundle_to_file::<DatabaseTokenGroup>(
            token,
            &request_path.with_extension(DatabaseTokenGroup::TOKEN_EXT),
        )
        .unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Chain {
                file: request_path,
                view_mode: ChainViewMode::AllCerts,
            },
            format: FormatMethod::PlainDigest,
        };

        inspect_token::run(&opts)
            .expect("inspect token tool should be able to infer request extension");
    }
}
