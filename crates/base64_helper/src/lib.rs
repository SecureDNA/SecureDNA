// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Base64 serialization helpers for 32-byte arrays
//! (Would be nice to support dynamic lengths, but lack of const generic
//! expression support makes it a pain to stack allocate)
//!
//! These helpers can be used by implementing Serialize / Deserialize and
//! delegating to them with the desired `base64` engine:
//!
//! ```rust
//! struct Unprefixed([u8; 32]);
//!
//! impl serde::Serialize for Unprefixed {
//!   fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//!     base64_helper::serialize(
//!       serializer,
//!       base64::engine::general_purpose::STANDARD,
//!       &self.0,
//!     )
//!   }
//! }
//!
//! impl<'de> serde::Deserialize<'de> for Unprefixed {
//!   fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
//!     base64_helper::deserialize(
//!       deserializer,
//!       base64::engine::general_purpose::STANDARD
//!     )
//!     .map(Self)
//!   }
//! }
//! ```
//!
//! There are also helpers for domain-separated prefixed types, which have the
//! base64 data prefixed with a desired ASCII character and exclamation mark
//! (e.g., `p!atCya...`). The prefix is checked at deserialization time and an error
//! is returned if it doesn't match what is expected.
//!
//! ```rust
//! struct Prefixed([u8; 32]);
//!
//! impl serde::Serialize for Prefixed {
//!   fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//!     base64_helper::serialize_with_prefix(
//!       serializer,
//!       base64::engine::general_purpose::STANDARD,
//!       b'p',
//!       &self.0,
//!     )
//!   }
//! }
//!
//! impl<'de> serde::Deserialize<'de> for Prefixed {
//!   fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
//!     base64_helper::deserialize_with_prefix(
//!       deserializer,
//!       base64::engine::general_purpose::STANDARD,
//!       'p',
//!     )
//!     .map(Self)
//!   }
//! }
//! ```

use std::borrow::Cow;

use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize to plain base64 string
pub fn serialize<S: Serializer>(
    serializer: S,
    engine: impl Engine,
    bytes: &[u8; 32],
) -> Result<S::Ok, S::Error> {
    // max bytes with padding
    const MAX_BYTES: usize = 47;
    let mut buf = [0_u8; MAX_BYTES];

    let n_bytes = engine.encode_slice(bytes, &mut buf).unwrap();
    let s = std::str::from_utf8(&buf[..n_bytes]).unwrap();

    serializer.serialize_str(s)
}

/// Serialize with an ASCII prefix char and exclamation point, e.g. `s!aGVsbG8...`
pub fn serialize_with_prefix<S: Serializer>(
    serializer: S,
    engine: impl Engine,
    prefix_char: u8,
    bytes: &[u8; 32],
) -> Result<S::Ok, S::Error> {
    // max bytes with padding
    const MAX_BYTES: usize = 47;
    let mut buf = [0_u8; MAX_BYTES + 2];
    buf[0] = prefix_char;
    buf[1] = b'!';

    let n_bytes = engine.encode_slice(bytes, &mut buf[2..]).unwrap();
    let s = std::str::from_utf8(&buf[..n_bytes + 2]).unwrap();

    serializer.serialize_str(s)
}

/// Deserialize from plain base64 string
pub fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
    engine: impl Engine,
) -> Result<[u8; 32], D::Error> {
    // TODO: why does serde need to allocate here sometimes?
    let s = Cow::<'de, str>::deserialize(deserializer)?;
    let bytes =
        deser_32byte_helper(engine, &s).ok_or(serde::de::Error::custom("expected 32 bytes"))?;
    Ok(bytes)
}

/// Deserialize, checking for the appropriate ASCII prefix char and exclamation point, e.g. `s!aGVsbG8...`
pub fn deserialize_with_prefix<'de, D: Deserializer<'de>>(
    deserializer: D,
    engine: impl Engine,
    prefix_char: char,
) -> Result<[u8; 32], D::Error> {
    // TODO: why does serde need to allocate here sometimes?
    let s = Cow::<'de, str>::deserialize(deserializer)?;

    // check the prefix
    if !s.chars().take(2).eq([prefix_char, '!'].iter().copied()) {
        return Err(serde::de::Error::custom(format!(
            "expected a string starting with \"{}!\", got {:?}",
            prefix_char,
            {
                // try to get the first two characters of `s`, falling back to first character, falling back to empty str
                let index = s
                    .char_indices()
                    .nth(1)
                    .map(|t| t.0)
                    .unwrap_or_else(|| s.char_indices().next().map(|t| t.0).unwrap_or(0));
                &s[0..index]
            }
        )));
    }

    // we checked the prefix so &s[2..] is panic-safe
    let bytes = deser_32byte_helper(engine, &s[2..])
        .ok_or(serde::de::Error::custom("expected 32 bytes"))?;

    if bytes == [0_u8; 32] || bytes == [1_u8; 32] {
        return Err(serde::de::Error::custom(
            "invalid nonce: all ones or all zeroes, should be random",
        ));
    }

    Ok(bytes)
}

/// Helper to deserialize a base64 string into a 32-byte array with no heap
/// allocations.
/// Returns `None` if the string does not represent 32 bytes of data.
fn deser_32byte_helper(engine: impl Engine, data: &str) -> Option<[u8; 32]> {
    // the base64 crate does a "conservative estimate" that is wrong
    // so we need to allocate extra space in this buffer and then cut it down
    let mut bytes = [0_u8; 40];
    let n_bytes = engine.decode_slice(data, &mut bytes);
    if n_bytes != Ok(32) {
        return None;
    }
    let [bytes @ .., _, _, _, _, _, _, _, _] = bytes;
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck::quickcheck! {
        fn no_prefix_rt(p: RistrettoLike) -> bool {
            let ser = serde_json::to_string(&p).unwrap();
            let de: RistrettoLike = serde_json::from_str(&ser).unwrap();
            p == de
        }

        fn prefix_rt(p: PrefixedRistrettoLike) -> bool {
            let ser = serde_json::to_string(&p).unwrap();
            let de: PrefixedRistrettoLike = serde_json::from_str(&ser).unwrap();
            p == de
        }

        fn prefix_required(p: RistrettoLike) -> bool {
            let ser = serde_json::to_string(&p).unwrap();
            serde_json::from_str::<PrefixedRistrettoLike>(&ser).is_err()
        }

        fn same_prefix_required(p: PrefixedRistrettoLike) -> bool {
            let ser = serde_json::to_string(&p).unwrap();
            assert!(ser.starts_with("\"t!"));
            let ser = ser.replace("\"t!", "\"s!");
            serde_json::from_str::<PrefixedRistrettoLike>(&ser).is_err()
        }

        fn prefix_rejected(p: PrefixedRistrettoLike) -> bool {
            let ser = serde_json::to_string(&p).unwrap();
            serde_json::from_str::<RistrettoLike>(&ser).is_err()
        }

        fn arb_string_no_panic(s: String) -> quickcheck::TestResult {
            // don't accidentally test a valid string
            if s.starts_with("\"p!") {
                quickcheck::TestResult::discard()
            } else if serde_json::from_str::<RistrettoLike>(&s).is_err() {
                quickcheck::TestResult::passed()
            } else {
                quickcheck::TestResult::failed()
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RistrettoLike([u8; 32]);

    impl serde::Serialize for RistrettoLike {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serialize(
                serializer,
                base64::engine::general_purpose::STANDARD,
                &self.0,
            )
        }
    }

    impl<'de> serde::Deserialize<'de> for RistrettoLike {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize(deserializer, base64::engine::general_purpose::STANDARD).map(Self)
        }
    }

    impl quickcheck::Arbitrary for RistrettoLike {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut arr: [u8; 32] = Default::default();
            for x in arr.iter_mut() {
                *x = quickcheck::Arbitrary::arbitrary(g);
            }
            Self(arr)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PrefixedRistrettoLike([u8; 32]);

    impl serde::Serialize for PrefixedRistrettoLike {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serialize_with_prefix(
                serializer,
                base64::engine::general_purpose::STANDARD,
                b't',
                &self.0,
            )
        }
    }

    impl<'de> serde::Deserialize<'de> for PrefixedRistrettoLike {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_with_prefix(deserializer, base64::engine::general_purpose::STANDARD, 't')
                .map(Self)
        }
    }

    impl quickcheck::Arbitrary for PrefixedRistrettoLike {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut arr: [u8; 32] = Default::default();
            for x in arr.iter_mut() {
                *x = quickcheck::Arbitrary::arbitrary(g);
            }
            Self(arr)
        }
    }
}
