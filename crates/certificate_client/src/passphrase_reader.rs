// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use once_cell::sync::Lazy;
use thiserror::Error;

pub const CREATE_KEY_PASSPHRASE_PROMPT: &str =
    "Please enter a passphrase to protect your private key:";

pub const CREATE_CERT_PASSPHRASE_PROMPT: &str =
    "Please enter a passphrase to protect your certificate's private key:";

pub const CREATE_TOKEN_PASSPHRASE_PROMPT: &str =
    "Please enter a passphrase to protect your token's private key:";

pub const CREATE_PASSPHRASE_REENTRY_PROMPT: &str = "Please re-enter passphrase to confirm:";

pub const ENTER_PASSPHRASE_PROMPT: &str =
    "Please enter the passphrase protecting your private key:";

pub const KEY_ENCRYPTION_PASSPHRASE_ENV_VAR: &str = "SECUREDNA_CERT_KEY_ENCRYPTION_PASSPHRASE";

pub static ENV_PASSPHRASE_WARNING: Lazy<String> = Lazy::new(|| {
    format!(
        "Using passphrase from environment variable {}; this is insecure\n",
        KEY_ENCRYPTION_PASSPHRASE_ENV_VAR
    )
});

pub trait PassphraseReader {
    fn read_passphrase(&self) -> Result<(String, PassphraseSource), PassphraseReaderError>;
}

/// This passphrase reader will prompt for a pre-existing passphrase
pub struct PromptExistingPassphraseReader {
    prompt: String,
}

impl PromptExistingPassphraseReader {
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
        }
    }
}

impl PassphraseReader for PromptExistingPassphraseReader {
    fn read_passphrase(&self) -> Result<(String, PassphraseSource), PassphraseReaderError> {
        let passphrase = rpassword::prompt_password(&self.prompt)
            .map_err(|_| PassphraseReaderError::PromptError)?;
        Ok((passphrase, PassphraseSource::Prompt))
    }
}

/// This passphrase reader will prompt to create a new passphrase. The passphrase will be confirmed via a second prompt.
pub struct PromptNewPassphraseReader {
    prompt: String,
}

impl PromptNewPassphraseReader {
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
        }
    }
}

impl PassphraseReader for PromptNewPassphraseReader {
    fn read_passphrase(&self) -> Result<(String, PassphraseSource), PassphraseReaderError> {
        let first_entry = rpassword::prompt_password(&self.prompt)
            .map_err(|_| PassphraseReaderError::PromptError)?;
        let second_entry = rpassword::prompt_password(CREATE_PASSPHRASE_REENTRY_PROMPT)
            .map_err(|_| PassphraseReaderError::PromptError)?;
        if first_entry != second_entry {
            Err(PassphraseReaderError::PassphraseConfirmationMismatch)
        } else {
            Ok((first_entry, PassphraseSource::Prompt))
        }
    }
}

/// This passphrase reader will check for the presence of the SECUREDNA_CERT_KEY_ENCRYPTION_PASSPHRASE
/// env variable from which to set the passphrase
pub struct EnvVarPassphraseReader;

impl PassphraseReader for EnvVarPassphraseReader {
    fn read_passphrase(&self) -> Result<(String, PassphraseSource), PassphraseReaderError> {
        if let Ok(passphrase) = std::env::var(KEY_ENCRYPTION_PASSPHRASE_ENV_VAR) {
            Ok((passphrase, PassphraseSource::EnvVar))
        } else {
            Err(PassphraseReaderError::EnvVariableNotFound)
        }
    }
}

// This passphrase reader reads the passphrase from memory
#[derive(Clone)]
pub struct MemoryPassphraseReader {
    pub passphrase: String,
}

#[cfg(test)]
impl MemoryPassphraseReader {
    pub fn wrong_passphrase(&self) -> String {
        format!("{}X", self.passphrase)
    }
}

impl Default for MemoryPassphraseReader {
    fn default() -> Self {
        Self {
            passphrase: "12345678".into(),
        }
    }
}

impl PassphraseReader for MemoryPassphraseReader {
    fn read_passphrase(&self) -> Result<(String, PassphraseSource), PassphraseReaderError> {
        Ok((self.passphrase.clone(), PassphraseSource::Memory))
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum PassphraseReaderError {
    #[error("Could not prompt for passphrase")]
    PromptError,
    #[error("Environment variable {KEY_ENCRYPTION_PASSPHRASE_ENV_VAR} not found")]
    EnvVariableNotFound,
    #[error("Unable to set a passphrase; the passphrases entered did not match")]
    PassphraseConfirmationMismatch,
}

#[derive(Debug, PartialEq)]
pub enum PassphraseSource {
    EnvVar,
    Prompt,
    Memory,
}

#[cfg(test)]
mod tests {
    use crate::passphrase_reader::{
        EnvVarPassphraseReader, PassphraseReader, PassphraseReaderError, PassphraseSource,
        KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
    };

    #[test]
    fn env_passphrase_reader_can_retrieve_passphrase() {
        let test_passphrase = "test_passphrase";

        let (passphrase, source) = temp_env::with_var(
            KEY_ENCRYPTION_PASSPHRASE_ENV_VAR,
            Some(test_passphrase),
            || EnvVarPassphraseReader.read_passphrase(),
        )
        .expect("env passphrase reader should retrieve passphrase when env var is set");

        assert_eq!(passphrase, test_passphrase);
        assert_eq!(source, PassphraseSource::EnvVar);
    }

    #[test]
    fn env_passphrase_reader_fails_gracefully() {
        let err = temp_env::with_var_unset(KEY_ENCRYPTION_PASSPHRASE_ENV_VAR, || {
            EnvVarPassphraseReader.read_passphrase()
        })
        .expect_err("env passphrase reader should error when env var not available");

        assert_eq!(err, PassphraseReaderError::EnvVariableNotFound);
    }
}
