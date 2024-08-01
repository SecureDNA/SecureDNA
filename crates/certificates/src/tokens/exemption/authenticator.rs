// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fmt::Display, str::FromStr};

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    SerializeDisplay,
    DeserializeFromStr,
)]
#[rasn(automatic_tags)]
pub struct YubikeyId([ModhexCharacter; Self::LEN]);

impl YubikeyId {
    const LEN: usize = 12;
    pub fn try_new<T: Into<String>>(id: T) -> Result<Self, ParseYubikeyIdError> {
        id.into().try_into()
    }
}

impl Display for YubikeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in &self.0 {
            write!(f, "{}", format!("{c:?}").to_ascii_lowercase())?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ParseYubikeyIdError {
    InvalidEntry(#[from] ParseModhexCharacterError),
    InvalidLength,
}

impl Display for ParseYubikeyIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseYubikeyIdError::InvalidEntry(e) => e.fmt(f),
            ParseYubikeyIdError::InvalidLength => {
                write!(f, "Invalid, should contain {} characters", YubikeyId::LEN)
            }
        }
    }
}

impl FromStr for YubikeyId {
    type Err = ParseYubikeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Check length is correct
        let set: [ModhexCharacter; Self::LEN] = s
            .chars()
            .map(|c| c.try_into())
            .collect::<Result<Vec<ModhexCharacter>, ParseModhexCharacterError>>()?
            .try_into()
            .map_err(|_| ParseYubikeyIdError::InvalidLength)?;

        Ok(Self(set))
    }
}

impl TryFrom<String> for YubikeyId {
    type Error = ParseYubikeyIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

// https://developers.yubico.com/OTP/OTPs_Explained.html
#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
)]
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum ModhexCharacter {
    #[default]
    C,
    B,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    N,
    R,
    T,
    U,
    V,
}

impl TryFrom<char> for ModhexCharacter {
    type Error = ParseModhexCharacterError;

    fn try_from(value: char) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase() {
            'c' => Ok(ModhexCharacter::C),
            'b' => Ok(ModhexCharacter::B),
            'd' => Ok(ModhexCharacter::D),
            'e' => Ok(ModhexCharacter::E),
            'f' => Ok(ModhexCharacter::F),
            'g' => Ok(ModhexCharacter::G),
            'h' => Ok(ModhexCharacter::H),
            'i' => Ok(ModhexCharacter::I),
            'j' => Ok(ModhexCharacter::J),
            'k' => Ok(ModhexCharacter::K),
            'l' => Ok(ModhexCharacter::L),
            'n' => Ok(ModhexCharacter::N),
            'r' => Ok(ModhexCharacter::R),
            't' => Ok(ModhexCharacter::T),
            'u' => Ok(ModhexCharacter::U),
            'v' => Ok(ModhexCharacter::V),
            x => Err(ParseModhexCharacterError(x)),
        }
    }
}

/// Device(s) used to authorize synthesis requests for exempt sequences
#[derive(
    AsnType,
    Decode,
    Encode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
)]
// tsgen = {Yubikey: string} | {Totp: string}
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum Authenticator {
    Yubikey(YubikeyId),
    Totp(String),
}

impl Display for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Authenticator::Yubikey(id) => write!(f, "Yubikey: {}", id),
            Authenticator::Totp(key) => write!(f, "TOTP: {}", key),
        }
    }
}

#[derive(Error, Debug)]
#[error("Invalid, contained non modhex character {0})")]
pub struct ParseModhexCharacterError(char);

#[cfg(test)]
mod tests {

    use crate::asn::{FromASN1DerBytes, ToASN1DerBytes};

    use super::*;

    #[test]
    fn yubikey_id_is_created_from_valid_input() {
        YubikeyId::try_new("cccjgjgkhcbb").expect("could not parse yubikey input");
    }

    #[test]
    fn parsing_yubikey_id_with_invalid_character_creates_error() {
        let result = YubikeyId::try_new("cccjgjgkhcab");
        assert!(matches!(
            result,
            Err(ParseYubikeyIdError::InvalidEntry(
                ParseModhexCharacterError('a')
            ))
        ));
    }

    #[test]
    fn parsing_yubikey_id_with_invalid_length_creates_error() {
        let result = YubikeyId::try_new("cccjgjgkhcbbb");
        assert!(matches!(result, Err(ParseYubikeyIdError::InvalidLength)));
    }

    #[test]
    fn can_encode_yubikey_id() {
        let id = YubikeyId::try_new("cccjgjgkhcbb").expect("could not parse");
        let encoded = id.to_der().unwrap();
        let id_decoded = YubikeyId::from_der(encoded).expect("could not decode yubikey");
        assert_eq!(id, id_decoded);
    }

    #[test]
    fn can_display_yubikey_id() {
        assert_eq!(
            YubikeyId::try_new("cccjgjgkhcbb").unwrap().to_string(),
            "cccjgjgkhcbb",
        )
    }
}
