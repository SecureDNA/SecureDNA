// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Display;

use rasn::{types::*, Decode, Encode};
use serde::{Deserialize, Serialize};
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
    Deserialize,
    Serialize,
)]
// tsgen
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
    #[error(transparent)]
    InvalidEntry(#[from] ParseModhexCharacterError),
    #[error("Invalid, should contain {} characters", YubikeyId::LEN)]
    InvalidLength,
}

impl TryFrom<String> for YubikeyId {
    type Error = ParseYubikeyIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Check length is correct
        let set: [ModhexCharacter; Self::LEN] = value
            .chars()
            .map(|c| c.try_into())
            .collect::<Result<Vec<ModhexCharacter>, ParseModhexCharacterError>>()?
            .try_into()
            .map_err(|_| ParseYubikeyIdError::InvalidLength)?;

        Ok(Self(set))
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
// tsgen
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
// tsgen
#[rasn(automatic_tags)]
#[rasn(choice)]
pub enum Authenticator {
    Yubikey(YubikeyId),
    Totp(String),
}

#[derive(Error, Debug)]
#[error("Invalid, contained non modhex character {0})")]
pub struct ParseModhexCharacterError(char);

#[cfg(test)]
mod tests {
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
    fn can_ber_encode_yubikey_id() {
        let id = YubikeyId::try_new("cccjgjgkhcbb").expect("could not parse");
        let encoded = rasn::der::encode(&id).unwrap();
        let id_decoded =
            rasn::der::decode::<YubikeyId>(&encoded).expect("could not decode yubikey");
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
