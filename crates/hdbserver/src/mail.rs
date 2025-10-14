// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Context;
use base64::{prelude::BASE64_STANDARD, Engine};
use bytes::Bytes;
use http_client::BaseApiClient;
use serde_json::{json, Value};
use tracing::warn;

use crate::mail_template::{AuditTemplate, AuditTemplateFields};

/// A way for the server to send mail. This is used when a cert is configured
/// with an `audit_email`: if a screening request is denied, we email the
/// customer about it.
pub struct MailService {
    pub sendgrid_api_key: String,
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

impl MailService {
    pub async fn send(&self, api_client: BaseApiClient, email: &Email) -> anyhow::Result<()> {
        let body: Value = json!({
            "personalizations": [{"to": [{"email": email.to_email, "name": email.to_name}]}],
            "from": {"email": email.from_email, "name": email.from_name},
            "subject": email.subject,
            "content": [{"type": "text/plain", "value": email.body}],
            "attachments": email.attachments.iter().map(|a| json!({
                "content": BASE64_STANDARD.encode(&a.content),
                "filename": a.filename,
                "type": a.content_type,
                "disposition": "attachment",
            })).collect::<Vec<_>>(),
        });

        let body_bytes =
            serde_json::to_vec(&body).context("Could not encode SendGrid API request")?;

        let response_bytes: Bytes = api_client
            .raw_post(
                "https://api.sendgrid.com/v3/mail/send",
                body_bytes.into(),
                "application/json",
                &[(
                    "Authorization".to_owned(),
                    format!("Bearer {}", self.sendgrid_api_key),
                )],
                None,
            )
            .await
            .context("Could not send SendGrid API request")?;

        if !response_bytes.is_empty() {
            warn!("Got non-empty success response from SendGrid: {response_bytes:?}");
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
    async fn can_send_mail_using_sendgrid() {
        let sendgrid_api_key = match std::env::var("SECUREDNA_TEST_SENDGRID_API_KEY") {
            Ok(val) if !val.is_empty() => val,
            _ => {
                debug!("SECUREDNA_TEST_SENDGRID_API_KEY is not set -- skipping SendGrid test.");
                return;
            }
        };

        let audit_template: AuditTemplate =
            toml::from_str(TEST_TEMPLATE).expect("failed to read audit template TOML file");

        let mail_service = MailService {
            sendgrid_api_key,
            audit_template,
        };

        let response = mail_service
            .send(
                BaseApiClient::new_external(),
                &Email {
                    from_email: "sendgrid@securedna.org".to_owned(),
                    from_name: "SecureDNA SendGrid test".to_owned(),
                    to_email: "lynn@securedna.org".to_owned(),
                    to_name: "SecureDNA SendGrid test recipient".to_owned(),
                    subject: "SecureDNA SendGrid test".to_owned(),
                    body: "It works!".to_owned(),
                    attachments: vec![Attachment {
                        content: b"The quick brown fox jumps over the lazy dog.".to_vec(),
                        content_type: "text/plain".to_owned(),
                        filename: "pangram.txt".to_owned(),
                    }],
                },
            )
            .await;
        assert_eq!(response.ok(), Some(()));
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
        assert!(err
            .to_string()
            .contains("unknown template variable {weird}"));
    }
}
