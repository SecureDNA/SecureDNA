// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Display;

use serde::Serialize;

use crate::display::{MultiItemDisplay, TruncatedMultiItemDisplay};
use crate::shared_components::common::CompatibleIdentity;
use crate::shared_components::digest::{INDENT, INDENT2};
use crate::{
    Authenticator, Description, ExemptionToken, ExemptionTokenRequest, Expiration, Id, Organism,
    PublicKey, Signature,
};

use super::et::{ExemptionTokenRequestVersion, ExemptionTokenVersion, ShippingAddress};

#[derive(Serialize)]
pub struct ExemptionTokenRequestDigest {
    version: String,
    request_id: Id,
    requestor: Description,
    public_key: Option<PublicKey>,
    requestor_auth_devices: Vec<Authenticator>,
    shipping_addresses: Vec<ShippingAddress>,
    exemptions: Vec<Organism>,
}

impl Display for ExemptionTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Exemption Token Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Requestor:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.requestor)?;
        if let Some(public_key) = self.public_key {
            writeln!(f, "{:INDENT$}Public Key:", "")?;
            writeln!(f, "{:INDENT2$}{}", "", public_key)?;
        }
        writeln!(f, "{:INDENT$}Shipping Addresses:", "")?;
        writeln!(
            f,
            "{}",
            MultiShippingAddressDisplay {
                items: &self.shipping_addresses,
                indent: INDENT2,
                separator: "\n\n",
                max_items: 3,
            }
        )?;
        writeln!(f, "{:INDENT$}Exemptions:", "")?;
        writeln!(
            f,
            "{}",
            TruncatedMultiItemDisplay {
                items: &self.exemptions,
                indent: INDENT2,
                separator: "\n",
                max_items: 5,
            }
        )?;
        writeln!(f, "{:INDENT$}Authentication Devices:", "")?;
        write!(
            f,
            "{}",
            TruncatedMultiItemDisplay {
                items: &self.requestor_auth_devices,
                indent: INDENT2,
                separator: "\n",
                max_items: 5,
            }
        )?;
        Ok(())
    }
}

impl From<ExemptionTokenRequest> for ExemptionTokenRequestDigest {
    fn from(value: ExemptionTokenRequest) -> Self {
        match value.version {
            ExemptionTokenRequestVersion::V1(r) => {
                let version = "V1".to_string();
                let request_id = r.request_id;
                let exemptions = r.exemptions;
                let requestor = r.requestor;
                let requestor_auth_devices = r.requestor_auth_devices;
                let shipping_addresses = r.shipping_addresses;
                let public_key = r.public_key;
                ExemptionTokenRequestDigest {
                    version,
                    request_id,
                    public_key,
                    exemptions,
                    requestor,
                    requestor_auth_devices,
                    shipping_addresses,
                }
            }
        }
    }
}

#[derive(Serialize)]
// tsgen
pub struct ExemptionTokenDigest {
    version: String,
    request_id: Id,
    issuance_id: Id,
    requestor: Description,
    public_key: Option<PublicKey>,
    shipping_addresses: Vec<ShippingAddress>,
    exemptions: Vec<Organism>,
    requestor_auth_devices: Vec<Authenticator>,
    issuer_auth_devices: Vec<Authenticator>,
    emails_to_notify: Vec<String>,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    signature: Signature,
}

impl<K> From<ExemptionToken<K>> for ExemptionTokenDigest {
    fn from(value: ExemptionToken<K>) -> Self {
        match value.version {
            ExemptionTokenVersion::V1(t) => {
                let version = "V1".to_string();
                let request_id = t.data.request.request_id;
                let requestor = t.data.request.requestor;
                let requestor_auth_devices = t.data.request.requestor_auth_devices;
                let shipping_addresses = t.data.request.shipping_addresses;
                let exemptions = t.data.request.exemptions;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let issued_by = t.data.issuer_fields.identity;
                let expiration = t.data.issuer_fields.expiration;
                let issuer_auth_devices = t.data.issuer_fields.issuer_auth_devices;
                let emails_to_notify = t.data.issuer_fields.emails_to_notify;
                let signature = t.signature;
                let public_key = t.data.request.public_key;

                ExemptionTokenDigest {
                    version,
                    request_id,
                    exemptions,
                    public_key,
                    requestor,
                    requestor_auth_devices,
                    shipping_addresses,
                    issuance_id,
                    issued_by,
                    expiration,
                    issuer_auth_devices,
                    emails_to_notify,
                    signature,
                }
            }
        }
    }
}

impl Display for ExemptionTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Exemption Token", self.version)?;
        writeln!(f, "{:INDENT$}Issuance ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issuance_id)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Requestor:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.requestor)?;
        if let Some(public_key) = self.public_key {
            writeln!(f, "{:INDENT$}Public Key:", "")?;
            writeln!(f, "{:INDENT2$}{}", "", public_key)?;
        }
        writeln!(f, "{:INDENT$}Shipping Addresses:", "")?;
        writeln!(
            f,
            "{}",
            MultiShippingAddressDisplay {
                items: &self.shipping_addresses,
                indent: INDENT2,
                separator: "\n\n",
                max_items: 3,
            }
        )?;
        writeln!(f, "{:INDENT$}Exemptions:", "")?;
        writeln!(
            f,
            "{}",
            TruncatedMultiItemDisplay {
                items: &self.exemptions,
                indent: INDENT2,
                separator: "\n",
                max_items: 5,
            }
        )?;
        writeln!(f, "{:INDENT$}Requestor Authentication Devices:", "")?;
        writeln!(
            f,
            "{}",
            TruncatedMultiItemDisplay {
                items: &self.requestor_auth_devices,
                indent: INDENT2,
                separator: "\n",
                max_items: 5,
            }
        )?;
        if !self.issuer_auth_devices.is_empty() {
            writeln!(f, "{:INDENT$}Issuer Authentication Devices:", "")?;
            writeln!(
                f,
                "{}",
                TruncatedMultiItemDisplay {
                    items: &self.issuer_auth_devices,
                    indent: INDENT2,
                    separator: "\n",
                    max_items: 5,
                }
            )?;
        }
        if !self.emails_to_notify.is_empty() {
            writeln!(f, "{:INDENT$}Emails to notify:", "")?;
            for email in &self.emails_to_notify {
                writeln!(f, "{:INDENT2$}{}", "", email)?;
            }
        }
        writeln!(f, "{:INDENT$}Issued by:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issued_by)?;
        writeln!(f, "{}", self.expiration)?;
        writeln!(f, "{:INDENT$}Signature:", "")?;
        write!(f, "{:INDENT2$}{}", "", self.signature)?;
        Ok(())
    }
}

struct MultiShippingAddressDisplay<'a> {
    items: &'a [ShippingAddress],
    indent: usize,
    separator: &'a str,
    max_items: usize,
}

impl<'a> Display for MultiShippingAddressDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addresses: Vec<_> = self
            .items
            .iter()
            .map(|address| MultiItemDisplay {
                items: address,
                indent: self.indent,
                separator: "\n",
                skip_first_indent: true,
            })
            .collect();

        write!(
            f,
            "{}",
            TruncatedMultiItemDisplay {
                items: &addresses,
                indent: self.indent,
                separator: self.separator,
                max_items: self.max_items,
            }
        )
    }
}
