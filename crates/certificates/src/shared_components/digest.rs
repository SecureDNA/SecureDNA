// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Display;

use time::{format_description::well_known::Rfc2822, OffsetDateTime};

use super::common::CompatibleIdentity;
use crate::Expiration;

pub const INDENT: usize = 2;
pub const INDENT2: usize = 2 * INDENT;

impl Display for Expiration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let issued_on = OffsetDateTime::from_unix_timestamp(self.not_valid_before)
            .map_err(|_| std::fmt::Error)?;
        let expires = OffsetDateTime::from_unix_timestamp(self.not_valid_after)
            .map_err(|_| std::fmt::Error)?;

        writeln!(f, "{:INDENT$}Issued on:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", issued_on.format(&Rfc2822).unwrap())?;
        writeln!(f, "{:INDENT$}Expires:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", expires.format(&Rfc2822).unwrap())?;
        Ok(())
    }
}

impl std::fmt::Display for CompatibleIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}(public key: {})",
            self.desc,
            if self.desc.is_empty() { "" } else { " " },
            self.pk
        )
    }
}
