// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::bail;
use certificates::{
    AuditRecipient, Issued, SynthesizerTokenGroup, TokenBundle, encrypt_for_recipient,
    key_traits::HasAssociatedSigningKey,
};
use hdb_api::HdbScreeningResult;
use http_client::BaseApiClient;
use tracing::error;

use crate::{
    event_store, mail::Attachment, mail_template::AuditTemplateFields, state::HdbServerState,
};

// Verify a screening result, if possible.
pub fn try_verify(
    hdbs_state: &HdbServerState,
    result: &HdbScreeningResult,
    synthclient_version: String,
    fasta_sha3_256_hex: String,
) -> anyhow::Result<HdbScreeningResult> {
    match &hdbs_state.verifier {
        None => {
            bail!(
                "Can't attach verifiable response in audit email because \
                verifier is not configured"
            );
        }
        Some(verifier) => {
            if result.verification.is_some() {
                Ok(result.clone())
            } else {
                verifier
                    .to_verifiable(result.base.clone(), synthclient_version, fasta_sha3_256_hex)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Can't attach verifiable response in audit email because \
                            serializing verifiable screening response failed: {e}"
                        )
                    })
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AuditReason {
    ExemptionExercised,
    HazardDenied,
}

async fn try_send_audit_email(
    audit_reason: AuditReason,
    hdbs_state: &HdbServerState,
    token_bundle: &TokenBundle<SynthesizerTokenGroup>,
    result: &HdbScreeningResult,
    recipient: &AuditRecipient,
) -> anyhow::Result<()> {
    let api_client = BaseApiClient::new_external();

    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let json_bytes = serde_json::to_vec(&result)?;
    let encrypted = encrypt_for_recipient(recipient.public_key(), &json_bytes)?;
    let attachment = Attachment {
        content: encrypted,
        content_type: "application/x-pem-file".to_owned(),
        filename: format!("encrypted-screening-result-{timestamp}.esr"),
    };

    let fields = AuditTemplateFields {
        reason: audit_reason,
        to_email: recipient.email().clone(),
        to_name: "SecureDNA user".to_owned(),
        manufacturer_domain: token_bundle.token.manufacturer_domain().clone(),
        synth_token_public_key: token_bundle.token.public_key().to_string(),
        model: token_bundle.token.model().clone(),
        serial_number: token_bundle.token.serial_number().clone(),
    };

    if let Some(service) = &hdbs_state.mail_service {
        service
            .send_using_audit_template(api_client, &fields, vec![attachment])
            .await
    } else {
        // In principle this should never happen, because if we detect that
        // audit email is not configured, we deny the request before ever
        // calling `send_audit_email_and_log` (which calls this function).
        bail!("Audit email is not configured");
    }
}

pub async fn send_audit_email_and_log(
    audit_reason: AuditReason,
    hdbs_state: &HdbServerState,
    token_bundle: &TokenBundle<SynthesizerTokenGroup>,
    result: &HdbScreeningResult,
    recipient: &AuditRecipient,
) {
    let error: Option<String> =
        try_send_audit_email(audit_reason, hdbs_state, token_bundle, result, recipient)
            .await
            .err()
            .map(|e| e.to_string());

    if let Err(e) = event_store::insert_audit_email_event(
        &hdbs_state.persistence_connection,
        *token_bundle.token.issuance_id(),
        recipient.email().clone(),
        recipient.public_key().to_string(),
        error,
    )
    .await
    {
        error!("Failed to log audit email event: {e}");
    }
}
