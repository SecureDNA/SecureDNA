// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Context;
use base64::{Engine, prelude::BASE64_STANDARD};
use bytes::Bytes;
use http_client::BaseApiClient;
use serde_json::{Value, json};
use tracing::{error, warn};

use crate::mail_template::{AuditTemplate, AuditTemplateFields};

/// A way for the server to send mail. This is used when a cert is configured
/// with an `audit_email`: if a screening request is denied, we email the
/// customer about it.
pub struct MailService {
    pub smtp2go_api_key: String,
    pub audit_template: AuditTemplate,
}

pub struct Attachment {
    pub content: Vec<u8>,
    pub content_type: String,
    pub filename: String,
}

pub struct Email {
    pub from_email: String,
    pub from_name: String,
    pub to_email: String,
    pub to_name: String,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<Attachment>,
}

/// Format a name and email into a string suitable for SMTP2GO, like `Name <email@example.com>`.
fn name_and_email(name: &str, email: &str) -> String {
    match name.trim() {
        "" => email.to_string(),
        trimmed => format!("{trimmed} <{email}>"),
    }
}

impl MailService {
    pub async fn send(&self, api_client: BaseApiClient, email: &Email) -> anyhow::Result<()> {
        let body: Value = json!({
            "sender": name_and_email(&email.from_name, &email.from_email),
            "to": [name_and_email(&email.to_name, &email.to_email)],
            "subject": email.subject,
            "text_body": email.body,
            "attachments": email.attachments.iter().map(|a| json!({
                "fileblob": BASE64_STANDARD.encode(&a.content),
                "filename": a.filename,
                "mimetype": a.content_type,
            })).collect::<Vec<_>>(),
        });

        let body_bytes =
            serde_json::to_vec(&body).context("Could not encode smtp2go API request")?;

        let response_bytes: Bytes = api_client
            .raw_post(
                "https://api.smtp2go.com/v3/email/send",
                body_bytes.into(),
                "application/json",
                &[("X-Smtp2go-Api-Key".to_owned(), self.smtp2go_api_key.clone())],
                None,
            )
            .await
            .map_err(|e| {
                error!("Error sending smtp2go API request: {e}");
                e
            })
            .context("Could not send smtp2go API request")?;

        if !response_bytes.is_empty() {
            warn!("Got non-empty success response from smtp2go: {response_bytes:?}");
        }
        Ok(())
    }

    pub async fn send_using_audit_template(
        &self,
        api_client: BaseApiClient,
        fields: &AuditTemplateFields,
        attachments: Vec<Attachment>,
    ) -> anyhow::Result<()> {
        let email = self
            .audit_template
            .make_email(fields, attachments)
            .with_context(|| {
                format!(
                    "Not sending email about {:?} because template is disabled.",
                    fields.reason
                )
            })?;
        self.send(api_client, &email).await
    }
}

#[cfg(test)]
mod tests {
    use tracing::debug;

    use crate::{audit::AuditReason, mail_template::AuditTemplateFields};

    use super::*;

    const TEST_TEMPLATE: &str = r#"from_email = "audit@securedna.org"
from_name = "SecureDNA (test)"
body = '''
(THIS IS A TEST)

You are receiving this email because the address {to_email} was configured
as a recipient for SecureDNA audit emails on a synthesis token associated
with {manufacturer_domain}:

    Public key: {synth_token_public_key}
    Model: {model}
    Serial number: {serial_number}

{event_description}

Attached to this email is an encrypted, auditable record of the screening
process, containing more information about the sequences matched by the
order. You may want to store this file somewhere safe, and you can inspect
it using the SecureDNA Inspector (<https://pages.securedna.org/inspect>).

To view the encrypted results, you will need the "-audit.priv" file that
was generated along with this synth token, and that file's passphrase.
If you've lost these files, contact SecureDNA.

(THIS IS A TEST)
'''

[exemption_exercised]
enabled = true
subject = "SecureDNA audit notice: exemption token used (THIS IS A TEST)"
event_description = '''
This token was just used to submit an order for a sequence of concern.
Synthesis permission was GRANTED because of an exemption token attached
to the request. (THIS IS A TEST)
'''

[hazard_denied]
enabled = true
subject = "SecureDNA audit notice: hazard denied (THIS IS A TEST)"
event_description = '''
This token was just used to attempt an order for a sequence of concern.
Synthesis permission was DENIED. (THIS IS A TEST)
'''
"#;

    #[tokio::test]
    async fn can_send_mail_using_smtp2go() {
        let smtp2go_api_key = match std::env::var("SECUREDNA_TEST_SMTP2GO_API_KEY") {
            Ok(val) if !val.is_empty() => val,
            _ => {
                debug!("SECUREDNA_TEST_SMTP2GO_API_KEY is not set -- skipping smtp2go test.");
                return;
            }
        };

        let audit_template: AuditTemplate =
            toml::from_str(TEST_TEMPLATE).expect("failed to read audit template TOML file");

        let mail_service = MailService {
            smtp2go_api_key,
            audit_template,
        };

        let response = mail_service
            .send(
                BaseApiClient::new_external(),
                &Email {
                    from_email: "audit@securedna.org".to_string(),
                    from_name: "SecureDNA smtp2go test".to_owned(),
                    to_email: "lynn@securedna.org".to_owned(),
                    to_name: "SecureDNA smtp2go test recipient".to_owned(),
                    subject: "SecureDNA smtp2go test".to_owned(),
                    body: "It works!".to_owned(),
                    attachments: vec![Attachment {
                        content: b"The quick brown fox jumps over the lazy dog.".to_vec(),
                        content_type: "text/plain".to_owned(),
                        filename: "pangram.txt".to_owned(),
                    }],
                },
            )
            .await;

        assert_eq!(response.unwrap(), ());
    }

    #[test]
    fn make_template_email() {
        let audit_template: AuditTemplate =
            toml::from_str(TEST_TEMPLATE).expect("failed to read audit template TOML file");

        let email = audit_template
            .make_email(
                &AuditTemplateFields {
                    reason: AuditReason::HazardDenied,
                    to_email: "gene@example.org".to_owned(),
                    to_name: "Gene Doe".to_owned(),
                    manufacturer_domain: "example.org".to_owned(),
                    synth_token_public_key: "public_key".to_owned(),
                    model: "XYZ123".to_owned(),
                    serial_number: "456789".to_owned(),
                },
                vec![],
            )
            .unwrap();
        assert_eq!(email.from_email, "audit@securedna.org");
        assert_eq!(email.from_name, "SecureDNA (test)");
        assert_eq!(email.to_email, "gene@example.org");
        assert_eq!(email.to_name, "Gene Doe");
        assert_eq!(
            email.subject,
            "SecureDNA audit notice: hazard denied (THIS IS A TEST)"
        );
        assert_eq!(
            email.body,
            r#"(THIS IS A TEST)

You are receiving this email because the address gene@example.org was configured
as a recipient for SecureDNA audit emails on a synthesis token associated
with example.org:

    Public key: public_key
    Model: XYZ123
    Serial number: 456789

This token was just used to attempt an order for a sequence of concern.
Synthesis permission was DENIED. (THIS IS A TEST)

Attached to this email is an encrypted, auditable record of the screening
process, containing more information about the sequences matched by the
order. You may want to store this file somewhere safe, and you can inspect
it using the SecureDNA Inspector (<https://pages.securedna.org/inspect>).

To view the encrypted results, you will need the "-audit.priv" file that
was generated along with this synth token, and that file's passphrase.
If you've lost these files, contact SecureDNA.

(THIS IS A TEST)
"#
        );
    }

    #[test]
    fn unknown_template_variable() {
        let err = toml::from_str::<AuditTemplate>(
            r#"from_email = "audit@securedna.org"
from_name = "SecureDNA (test)"
body = '''
This body has {to_email} in it but also a {weird} variable.
'''

[exemption_exercised]
enabled = true
subject = ""
event_description = ""

[hazard_denied]
enabled = true
subject = ""
event_description = ""
"#,
        )
        .err()
        .expect("should error");
        assert!(
            err.to_string()
                .contains("unknown template variable {weird}")
        );
    }
}
