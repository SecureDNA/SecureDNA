// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Display;

use serde::Serialize;

use crate::{
    shared_components::common::CompatibleIdentity, AuditRecipient, Expiration, Id, PublicKey,
    Signature, SynthesizerToken, SynthesizerTokenRequest,
};

use super::synthesizer::{SynthesizerTokenRequestVersion, SynthesizerTokenVersion};
use crate::shared_components::digest::{INDENT, INDENT2};

#[derive(Serialize)]
pub struct SynthesizerTokenRequestDigest {
    version: String,
    request_id: Id,
    public_key: PublicKey,
    manufacturer_domain: String,
    model: String,
    serial_number: String,
    max_dna_base_pairs_per_day: u64,
    audit_recipient: Option<AuditRecipient>,
}

impl From<SynthesizerTokenRequest> for SynthesizerTokenRequestDigest {
    fn from(value: SynthesizerTokenRequest) -> Self {
        match value.version {
            SynthesizerTokenRequestVersion::V1(r) => {
                let version = "V1".to_string();
                let request_id = r.request_id;
                let public_key = r.public_key;
                let manufacturer_domain = r.manufacturer_domain;
                let model = r.model;
                let serial_number = r.serial_number;
                let max_dna_base_pairs_per_day = r.max_dna_base_pairs_per_day;
                let audit_recipient = r.audit_recipient;
                SynthesizerTokenRequestDigest {
                    version,
                    request_id,
                    public_key,
                    manufacturer_domain,
                    model,
                    serial_number,
                    max_dna_base_pairs_per_day,
                    audit_recipient,
                }
            }
        }
    }
}

impl Display for SynthesizerTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Synthesizer Token Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Manufacturer Domain:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.manufacturer_domain)?;
        writeln!(f, "{:INDENT$}Model:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.model)?;
        writeln!(f, "{:INDENT$}Serial Number:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.serial_number)?;
        writeln!(f, "{:INDENT$}Rate Limit:", "")?;
        write!(
            f,
            "{:INDENT2$}{} base pairs per day",
            "", self.max_dna_base_pairs_per_day
        )?;
        if let Some(audit_recipient) = &self.audit_recipient {
            writeln!(f, "\n{:INDENT$}Audit Recipient:", "")?;
            write!(
                f,
                "{:INDENT2$}{} ({})",
                "", audit_recipient.email, audit_recipient.public_key
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct SynthesizerTokenDigest {
    version: String,
    request_id: Id,
    issuance_id: Id,
    public_key: PublicKey,
    manufacturer_domain: String,
    model: String,
    serial_number: String,
    max_dna_base_pairs_per_day: u64,
    audit_recipient: Option<AuditRecipient>,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    signature: Signature,
}

impl<K> From<SynthesizerToken<K>> for SynthesizerTokenDigest {
    fn from(value: SynthesizerToken<K>) -> Self {
        match value.version {
            SynthesizerTokenVersion::V1(t) => {
                let version = "V1".to_string();

                let request_id = t.data.request.request_id;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let public_key = t.data.request.public_key;
                let manufacturer_domain = t.data.request.manufacturer_domain;
                let model = t.data.request.model;
                let serial_number = t.data.request.serial_number;
                let max_dna_base_pairs_per_day = t.data.request.max_dna_base_pairs_per_day;
                let audit_recipient = t.data.request.audit_recipient;
                let expiration = t.data.issuer_fields.expiration;
                let signature = t.signature;
                let issued_by = t.data.issuer_fields.identity;

                SynthesizerTokenDigest {
                    version,
                    request_id,
                    issuance_id,
                    public_key,
                    manufacturer_domain,
                    model,
                    serial_number,
                    max_dna_base_pairs_per_day,
                    audit_recipient,
                    expiration,
                    signature,
                    issued_by,
                }
            }
        }
    }
}

impl Display for SynthesizerTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Synthesizer Token", self.version)?;
        writeln!(f, "{:INDENT$}Issuance ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issuance_id)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Manufacturer Domain:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.manufacturer_domain)?;
        writeln!(f, "{:INDENT$}Model:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.model)?;
        writeln!(f, "{:INDENT$}Serial Number:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.serial_number)?;
        writeln!(f, "{:INDENT$}Rate Limit:", "")?;
        writeln!(
            f,
            "{:INDENT2$}{} base pairs per day",
            "", self.max_dna_base_pairs_per_day
        )?;
        if let Some(audit_recipient) = &self.audit_recipient {
            writeln!(f, "{:INDENT$}Audit Recipient:", "")?;
            writeln!(
                f,
                "{:INDENT2$}{} ({})",
                "", audit_recipient.email, audit_recipient.public_key
            )?;
        }
        writeln!(f, "{:INDENT$}Issued by:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issued_by)?;
        writeln!(f, "{}", self.expiration)?;
        writeln!(f, "{:INDENT$}Signature:", "")?;
        write!(f, "{:INDENT2$}{}", "", self.signature)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        test_helpers::{create_leaf_cert, expected_synthesizer_token_display},
        Digestible, Expiration, Issued, KeyPair, Manufacturer, SynthesizerTokenRequest,
    };

    #[test]
    fn digest_display_for_synthesizer_token_without_audit_recipient_matches_expected_display() {
        let cert = create_leaf_cert::<Manufacturer>();
        let kp = KeyPair::new_random();
        let req = SynthesizerTokenRequest::v1_token_request(
            kp.public_key(),
            "maker.synth",
            "XL",
            "10AK",
            10_000u64,
            None,
        );
        let token = cert
            .issue_synthesizer_token(req, Expiration::default())
            .unwrap();
        let expected_text = expected_synthesizer_token_display(
            &token,
            "maker.synth",
            "XL",
            "10AK",
            "10000 base pairs per day",
            None,
            &format!("(public key: {})", token.issuer_public_key()),
        );
        let text = token.into_digest().to_string();
        assert_eq!(text, expected_text);
    }
}
