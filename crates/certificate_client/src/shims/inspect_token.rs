// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Functionality for inspecting the contents of a certificate or certificate request

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use clap::{crate_version, Parser, Subcommand};

use super::error::CertCliError;
use crate::inspect::{
    ChainViewMode, FormatMethod, Formattable, MultiItemOutput, SingleRequestOutput,
};
use certificates::{
    file::{
        load_token_bundle_from_file, load_token_request_from_file, save_attachment_to_directory,
        TokenExtension,
    },
    Attachment, DatabaseTokenGroup, ExemptionTokenGroup, HltTokenGroup, KeyserverTokenGroup,
    SynthesizerTokenGroup, TokenBundle, TokenGroup, TokenKind, VerifierTokenGroup,
};

#[derive(Debug, Parser)]
#[clap(
    name = "sdna-inspect-token",
    about = "Inspects and validates a SecureDNA token, token request, or a token's certificate chain",
    version = crate_version!()
)]
pub struct InspectTokenOpts {
    #[clap(
        help = "Type of token [possible values: keyserver, exemption, database, synthesizer, hlt]"
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
    #[clap(help = "Extract any attachments contained in the token into this directory")]
    pub extract_attachments: Option<PathBuf>,
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

pub enum LoadedTarget<T: TokenGroup> {
    Request(T::TokenRequest),
    Token(TokenBundle<T>),
    Chain(TokenBundle<T>, ChainViewMode),
}

impl Target {
    pub fn load_from_file<T: TokenGroup + TokenExtension>(
        &self,
    ) -> Result<LoadedTarget<T>, CertCliError> {
        match self {
            Target::Request { file } => {
                let file = match file.extension() {
                    Some(_) => file.to_owned(),
                    None => file.with_extension(T::REQUEST_EXT),
                };
                let request = load_token_request_from_file::<T>(&file)?;
                Ok(LoadedTarget::Request(request))
            }
            Target::Token { file } => {
                let file = match file.extension() {
                    Some(_) => file.to_owned(),
                    None => file.with_extension(T::TOKEN_EXT),
                };
                let token_bundle = load_token_bundle_from_file::<T>(&file)?;
                Ok(LoadedTarget::Token(token_bundle))
            }
            Target::Chain { file, view_mode } => {
                let file = match file.extension() {
                    Some(_) => file.to_owned(),
                    None => file.with_extension(T::TOKEN_EXT),
                };
                let token_bundle = load_token_bundle_from_file::<T>(&file)?;
                Ok(LoadedTarget::Chain(token_bundle, view_mode.to_owned()))
            }
        }
    }

    pub fn inspect<T: TokenGroup + TokenExtension>(
        &self,
        format_method: &FormatMethod,
    ) -> Result<String, CertCliError> {
        self.load_from_file::<T>()?.display(format_method)
    }
}

impl<T: TokenGroup> LoadedTarget<T> {
    pub fn display(self, format_method: &FormatMethod) -> Result<String, CertCliError> {
        match self {
            LoadedTarget::Request(request) => SingleRequestOutput(request)
                .format(format_method)
                .map_err(CertCliError::from),
            LoadedTarget::Token(token_bundle) => {
                MultiItemOutput::from_items(vec![token_bundle.token])
                    .format(format_method)
                    .map_err(CertCliError::from)
            }
            LoadedTarget::Chain(token_bundle, view_mode) => {
                view_mode.display_chain(token_bundle, format_method)
            }
        }
    }
}

impl LoadedTarget<ExemptionTokenGroup> {
    fn attachments(&self) -> &[Attachment] {
        match self {
            LoadedTarget::Request(request) => request.attachments(),
            LoadedTarget::Token(bundle) | LoadedTarget::Chain(bundle, _) => {
                bundle.token.request_attachments()
            }
        }
    }

    pub fn extract_attachments(&self, path: &Path) -> Result<String, CertCliError> {
        let mut lines: Vec<String> = vec![];
        let path_name = path.to_str().unwrap_or("(non-unicode path)");
        for attachment in self.attachments() {
            save_attachment_to_directory(attachment, path)?;
            lines.push(format!("Extracted {} to {path_name}", attachment.name));
        }
        if lines.is_empty() {
            lines.push("This file has no attachments.".to_owned());
        }
        Ok(lines.join("\n") + "\n\n")
    }
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
        TokenKind::Exemption => {
            let mut output = String::new();
            let target = opts.target.load_from_file::<ExemptionTokenGroup>()?;
            if let Some(extract_attachments) = &opts.extract_attachments {
                output += &target.extract_attachments(extract_attachments)?;
            }
            output += &target.display(&opts.format)?;
            Ok(output)
        }
        TokenKind::Keyserver => opts.target.inspect::<KeyserverTokenGroup>(&opts.format),
        TokenKind::Database => opts.target.inspect::<DatabaseTokenGroup>(&opts.format),
        TokenKind::Verifier => opts.target.inspect::<VerifierTokenGroup>(&opts.format),
        TokenKind::Hlt => opts.target.inspect::<HltTokenGroup>(&opts.format),
        TokenKind::Synthesizer => opts.target.inspect::<SynthesizerTokenGroup>(&opts.format),
    }
}

#[cfg(all(test, feature = "cert_tests"))]
mod tests {
    use std::fs;

    use certificates::{Digestible, KeyserverTokenGroup, SystemClock, TokenBundle};
    use tempfile::TempDir;

    use certificates::file::{
        save_token_bundle_to_file, save_token_request_to_file, FileError, TokenExtension,
    };
    use certificates::test_helpers::{
        create_etr_with_options, create_leaf_bundle, create_leaf_cert,
    };
    use certificates::{
        test_helpers::{
            create_database_token_bundle, create_hlt_token_bundle, create_intermediate_bundle,
            create_keyserver_token_bundle, create_synthesizer_token_bundle,
            create_verifier_token_bundle, expected_database_token_display,
            expected_hlt_token_display, expected_keyserver_token_display,
            expected_synthesizer_token_display, expected_verifier_token_display,
            BreakableSignature,
        },
        Builder, DatabaseTokenGroup, DatabaseTokenRequest, ExemptionTokenGroup, Expiration,
        Infrastructure, Issued, IssuerAdditionalFields, KeyserverTokenRequest, RequestBuilder,
        SigningKeyPair, TokenKind,
    };
    use doprf::party::KeyserverId;

    use super::{run, InspectTokenOpts, Target};
    use crate::inspect::{ChainViewMode, FormatMethod, NO_EXCLUDED_CERTS_TEXT, NO_PATH_FOUND_TEXT};
    use crate::shims::{error::CertCliError, inspect_token};

    #[test]
    fn inspect_plaintext_display_for_database_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.dt");

        let (token_bundle, _) = create_database_token_bundle();
        let expected_text = expected_database_token_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
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
        let mut expected_text = expected_database_token_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_verifier_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.vt");

        let (token_bundle, _) = create_verifier_token_bundle();
        let expected_text = expected_verifier_token_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Verifier,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_verifier_token_warns_if_signature_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.vt");

        let (mut token_bundle, _) = create_verifier_token_bundle();
        token_bundle.token.break_signature();
        let mut expected_text = expected_verifier_token_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Verifier,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_hlt_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.ht");

        let (token_bundle, _) = create_hlt_token_bundle();
        let expected_text = expected_hlt_token_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Hlt,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
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
        let mut expected_text = expected_hlt_token_display(
            &token_bundle.token,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Hlt,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_keyserver_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.kt");

        let (token_bundle, _) = create_keyserver_token_bundle();
        let expected_text = expected_keyserver_token_display(
            &token_bundle.token,
            "1",
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
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
        let mut expected_text = expected_keyserver_token_display(
            &token_bundle.token,
            "1",
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
        };
        let text = run(&opts).unwrap();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn inspect_plaintext_display_for_synthesizer_token_matches_expected_display() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.st");

        let (token_bundle, _) = create_synthesizer_token_bundle();

        let expected_text = expected_synthesizer_token_display(
            &token_bundle.token,
            "maker.synth",
            "XL",
            "10AK",
            "10000 base pairs per day",
            None,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Synthesizer,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
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
        let mut expected_text = expected_synthesizer_token_display(
            &token_bundle.token,
            "maker.synth",
            "XL",
            "10AK",
            "10000 base pairs per day",
            None,
            &format!("(public key: {})", token_bundle.token.issuer_public_key()),
        );
        expected_text.push_str("\nINVALID: The signature failed verification");

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Synthesizer,
            target: Target::Token { file: token_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
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
            extract_attachments: None,
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

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req =
            RequestBuilder::<Infrastructure>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_req, IssuerAdditionalFields::default(), int_kp)
            .unwrap();

        let token_kp = SigningKeyPair::new_random();
        let token_request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());

        let token_bundle = leaf_bundle
            .issue_database_token_bundle(token_request, Expiration::default(), leaf_kp)
            .unwrap();
        save_token_bundle_to_file(token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Database,
            target: Target::Chain {
                file: token_path,
                view_mode: ChainViewMode::AllCerts,
            },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
        };

        let result = run(&opts).unwrap();

        // check 'AllCerts' contains leaf cert and int cert
        let int_cert_display = int_bundle
            .get_lead_cert(&SystemClock)
            .unwrap()
            .clone()
            .into_digest()
            .to_string();
        let leaf_cert_display = leaf_bundle
            .get_lead_cert(&SystemClock)
            .unwrap()
            .clone()
            .into_digest()
            .to_string();

        assert!(result.contains(&int_cert_display));
        assert!(result.contains(&leaf_cert_display));
    }

    #[test]
    fn inspect_correctly_shows_path_to_issuer_of_token_chain() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.dt");

        let (int_bundle, int_kp, root_public_key) = create_intermediate_bundle::<Infrastructure>();

        let leaf_kp = SigningKeyPair::new_random();
        let leaf_req =
            RequestBuilder::<Infrastructure>::leaf_v1_builder(leaf_kp.public_key()).build();

        let leaf_bundle = int_bundle
            .issue_cert_bundle(leaf_req, IssuerAdditionalFields::default(), int_kp)
            .unwrap();

        let token_kp = SigningKeyPair::new_random();
        let token_request = DatabaseTokenRequest::v1_token_request(token_kp.public_key());

        let token_bundle = leaf_bundle
            .issue_database_token_bundle(token_request, Expiration::default(), leaf_kp)
            .unwrap();
        let token = token_bundle.token.clone();
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
            extract_attachments: None,
        };

        let result = run(&opts).unwrap();

        // check that path to issuer contains leaf cert and int cert
        let int_cert_display = int_bundle.certs[0].clone().into_digest().to_string();
        let leaf_cert_display = leaf_bundle.certs[0].clone().into_digest().to_string();
        let token_display = token.into_digest().to_string();

        let mut expected_text = "Path 1:\n".to_owned();
        expected_text.push_str(&token_display);
        expected_text.push_str("\n\n");
        expected_text.push_str(&leaf_cert_display);
        expected_text.push_str("\n\n");
        expected_text.push_str(&int_cert_display);

        assert_eq!(result, expected_text);
    }

    #[test]
    fn inspect_correctly_identifies_redundant_certificates_in_token_chain() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.kt");

        let (leaf_bundle, leaf_kp, root_public_key) = create_leaf_bundle::<Infrastructure>();
        let token_request = KeyserverTokenRequest::v1_token_request(
            SigningKeyPair::new_random().public_key(),
            KeyserverId::try_from(1).unwrap(),
        );
        let token_bundle = leaf_bundle
            .issue_keyserver_token_bundle(token_request, Expiration::default(), leaf_kp)
            .unwrap();

        let mut keyserver_chain = leaf_bundle.issue_chain();
        let extra_cert = create_leaf_cert().into_key_unavailable();
        keyserver_chain.add_item(extra_cert.clone());

        let modified_token_bundle: TokenBundle<KeyserverTokenGroup> =
            TokenBundle::new(token_bundle.token, keyserver_chain);

        save_token_bundle_to_file(modified_token_bundle, &token_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Chain {
                file: token_path,
                view_mode: ChainViewMode::NotPartOfPath {
                    public_keys: vec![root_public_key],
                },
            },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
        };

        let result = run(&opts).unwrap();

        let expected_text = extra_cert.into_digest().to_string();
        assert_eq!(result, expected_text)
    }

    #[test]
    fn inspect_correctly_identifies_cases_where_no_path_to_issuer_exists() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("token.kt");

        let (token_bundle, _) = create_keyserver_token_bundle();

        save_token_bundle_to_file(token_bundle, &token_path).unwrap();
        let incorrect_root_key = SigningKeyPair::new_random().public_key();

        let opts = InspectTokenOpts {
            token: TokenKind::Keyserver,
            target: Target::Chain {
                file: token_path,
                view_mode: ChainViewMode::AllPaths {
                    public_keys: vec![incorrect_root_key],
                },
            },
            format: FormatMethod::PlainDigest,
            extract_attachments: None,
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
            extract_attachments: None,
        };

        let result = run(&opts).unwrap();
        assert_eq!(&result, NO_EXCLUDED_CERTS_TEXT)
    }

    #[test]
    fn inspect_request_infers_extension_if_not_provided() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("token");

        let kp = SigningKeyPair::new_random();
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
            extract_attachments: None,
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
            extract_attachments: None,
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
            extract_attachments: None,
        };

        inspect_token::run(&opts)
            .expect("inspect token tool should be able to infer request extension");
    }

    #[test]
    fn extract_exemption_request_attachments() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("token.etr");

        let etr = create_etr_with_options(None, vec![], vec![]);
        save_token_request_to_file::<ExemptionTokenGroup>(etr, &request_path).unwrap();

        let opts = InspectTokenOpts {
            token: TokenKind::Exemption,
            target: Target::Request { file: request_path },
            format: FormatMethod::PlainDigest,
            extract_attachments: Some(temp_dir.path().join("attachments")),
        };
        run(&opts).unwrap();

        // Attachment specified in `create_etr_with_options` in certificates/src/test_helpers.rs
        let path = temp_dir.path().join("attachments").join("testfile.txt");
        assert_eq!(fs::read_to_string(&path).unwrap(), "abc");
    }
}
