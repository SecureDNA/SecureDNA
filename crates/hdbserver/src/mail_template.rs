// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    audit::AuditReason,
    mail::{Attachment, Email},
};

#[derive(Default, Serialize, Deserialize)]
pub struct AuditEventTemplate {
    enabled: bool,
    subject: String,
    event_description: String,
}

#[derive(Deserialize)]
pub struct AuditTemplate {
    from_email: String,
    from_name: String,
    #[serde(deserialize_with = "ParsedTemplateBody::deserialize")]
    body: ParsedTemplateBody,
    exemption_exercised: AuditEventTemplate,
    hazard_denied: AuditEventTemplate,
}

pub struct AuditTemplateFields {
    pub reason: AuditReason,
    pub to_email: String,
    pub to_name: String,
    pub manufacturer_domain: String,
    pub synth_token_public_key: String,
    pub model: String,
    pub serial_number: String,
}

enum TemplateVariable {
    ToEmail,
    ToName,
    FromEmail,
    FromName,
    ManufacturerDomain,
    SynthTokenPublicKey,
    Model,
    SerialNumber,
    EventDescription,
}

impl TemplateVariable {
    fn parse(name: &str) -> Result<Self, String> {
        match name {
            "to_email" => Ok(Self::ToEmail),
            "to_name" => Ok(Self::ToName),
            "from_email" => Ok(Self::FromEmail),
            "from_name" => Ok(Self::FromName),
            "manufacturer_domain" => Ok(Self::ManufacturerDomain),
            "synth_token_public_key" => Ok(Self::SynthTokenPublicKey),
            "model" => Ok(Self::Model),
            "serial_number" => Ok(Self::SerialNumber),
            "event_description" => Ok(Self::EventDescription),
            _ => Err(format!("unknown template variable {{{name}}}")),
        }
    }

    fn fill<'a>(&self, template: &'a AuditTemplate, fields: &'a AuditTemplateFields) -> &'a str {
        match self {
            Self::ToEmail => &fields.to_email,
            Self::ToName => &fields.to_name,
            Self::FromEmail => &template.from_email,
            Self::FromName => &template.from_name,
            Self::ManufacturerDomain => &fields.manufacturer_domain,
            Self::SynthTokenPublicKey => &fields.synth_token_public_key,
            Self::Model => &fields.model,
            Self::SerialNumber => &fields.serial_number,
            Self::EventDescription => match fields.reason {
                AuditReason::ExemptionExercised => &template.exemption_exercised.event_description,
                AuditReason::HazardDenied => &template.hazard_denied.event_description,
            },
        }
        .trim()
    }
}

enum TemplatePart {
    Literal(String),
    Variable(TemplateVariable),
}

struct ParsedTemplateBody {
    parts: Vec<TemplatePart>,
}

impl ParsedTemplateBody {
    pub fn fill(&self, template: &AuditTemplate, fields: &AuditTemplateFields) -> String {
        self.parts
            .iter()
            .map(|part| match part {
                TemplatePart::Literal(lit) => lit,
                TemplatePart::Variable(var) => var.fill(template, fields),
            })
            .collect()
    }

    pub fn parse(body: &str) -> Result<Self, String> {
        let mut parts = vec![];
        let mut in_variable = false;
        let mut buffer = String::new();
        for c in body.chars() {
            if in_variable {
                if c.is_whitespace() {
                    return Err("unexpected whitespace in template variable".to_owned());
                }
                match c {
                    '{' => return Err("unexpected opening brace in template variable".to_owned()),
                    '}' => {
                        parts.push(TemplatePart::Variable(TemplateVariable::parse(&buffer)?));
                        buffer = String::new();
                        in_variable = false;
                    }
                    _ => buffer.push(c),
                }
            } else {
                match c {
                    '{' => {
                        parts.push(TemplatePart::Literal(buffer));
                        buffer = String::new();
                        in_variable = true;
                    }
                    '}' => {
                        return Err(
                            "unexpected closing brace outside of template variable".to_owned()
                        )
                    }
                    _ => buffer.push(c),
                }
            }
        }
        if in_variable {
            return Err("unclosed brace at end of template".to_owned());
        }
        parts.push(TemplatePart::Literal(buffer));
        Ok(ParsedTemplateBody { parts })
    }
}

impl<'de> Deserialize<'de> for ParsedTemplateBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::parse(&string).map_err(serde::de::Error::custom)
    }
}

impl AuditTemplate {
    /// Make an `Email` about the event described by `fields`.
    /// If the template for that event type is disabled, return `None`.
    pub fn make_email(
        &self,
        fields: &AuditTemplateFields,
        attachments: Vec<Attachment>,
    ) -> Option<Email> {
        let event = match fields.reason {
            AuditReason::ExemptionExercised => &self.exemption_exercised,
            AuditReason::HazardDenied => &self.hazard_denied,
        };

        if !event.enabled {
            return None;
        }

        let body = self.body.fill(self, fields);

        Some(Email {
            from_name: self.from_name.clone(),
            from_email: self.from_email.clone(),
            to_email: fields.to_email.clone(),
            to_name: fields.to_name.clone(),
            subject: event.subject.clone(),
            body,
            attachments,
        })
    }
}
