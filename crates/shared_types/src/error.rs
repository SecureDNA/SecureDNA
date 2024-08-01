// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use certificates::{ChainValidationError, Infrastructure, PublicKey, Role, TokenKind};

use std::fmt::Display;

#[derive(Debug, thiserror::Error)]
pub struct InvalidClientTokenBundle<R: Role> {
    pub error: ChainValidationError<R>,
    pub token_kind: TokenKind,
}

impl<R: Role> Display for InvalidClientTokenBundle<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.error.invalid_items.is_empty() {
            write!(
                f,
                "the {} provided does not originate from the expected root certificate. This indicates a configuration error.",
                self.token_kind
            )
        } else {
            write!(
                f,
                "the following items in the {} file are invalid: {}",
                self.token_kind,
                self.error.user_friendly_text()
            )
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub struct InvalidInfrastructureTokenBundle {
    pub error: ChainValidationError<Infrastructure>,
    pub token_kind: TokenKind,
    pub roots: Vec<PublicKey>,
}

impl Display for InvalidInfrastructureTokenBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.error.invalid_items.is_empty() {
            write!(
                f,
                "the {} provided does not originate from the expected roots. Expected root(s): {}",
                self.token_kind,
                self.roots
                    .iter()
                    .map(|pk| pk.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            write!(
                f,
                "the following items in the {} file are invalid:\n{}",
                self.token_kind,
                self.error.user_friendly_text()
            )
        }
    }
}
