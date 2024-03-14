// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! base64-encoded client / server nonces with prefixes

use rand::prelude::*;

/// A 32-byte client nonce, encoded as "c!{base64 data}"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientNonce(Nonce);

/// A 32-byte server nonce, encoded as "s!{base64 data}"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerNonce(Nonce);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; 32]);

impl ClientNonce {
    /// Serialize a ClientNonce to standard base64 without a c! prefix
    pub fn to_plain_base64(&self) -> String {
        self.0.as_plain_base64()
    }
}

impl Distribution<ClientNonce> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ClientNonce {
        ClientNonce(rng.gen())
    }
}

impl ServerNonce {
    /// Serialize a ServerNonce to standard base64 without an s! prefix
    pub fn to_plain_base64(&self) -> String {
        self.0.as_plain_base64()
    }
}

impl Distribution<ServerNonce> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ServerNonce {
        ServerNonce(rng.gen())
    }
}

impl Nonce {
    /// Make a new Nonce. Returns None if the bytes are [0; 32] or [1; 32]
    /// which are invalid Nonce values.
    fn new(bytes: [u8; 32]) -> Option<Self> {
        if bytes == [0; 32] || bytes == [1; 32] {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// Serialize a nonce to standard base64 without a prefix
    fn as_plain_base64(&self) -> String {
        crate::base64::encode(self.0)
    }
}

impl Distribution<Nonce> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Nonce {
        loop {
            let mut bytes: [u8; 32] = Default::default();
            rng.fill_bytes(&mut bytes);
            if let Some(nonce) = Nonce::new(bytes) {
                return nonce;
            }
        }
    }
}

impl serde::Serialize for ClientNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        base64_helper::serialize_with_prefix(serializer, crate::base64::B64, b'c', &self.0 .0)
    }
}

impl<'de> serde::Deserialize<'de> for ClientNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        base64_helper::deserialize_with_prefix(deserializer, crate::base64::B64, 'c')
            .and_then(de_nonce::<'de, D>)
            .map(ClientNonce)
    }
}

impl serde::Serialize for ServerNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        base64_helper::serialize_with_prefix(serializer, crate::base64::B64, b's', &self.0 .0)
    }
}

impl<'de> serde::Deserialize<'de> for ServerNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        base64_helper::deserialize_with_prefix(deserializer, crate::base64::B64, 's')
            .and_then(de_nonce::<'de, D>)
            .map(ServerNonce)
    }
}

fn de_nonce<'de, D: serde::Deserializer<'de>>(bytes: [u8; 32]) -> Result<Nonce, D::Error> {
    Nonce::new(bytes).ok_or(serde::de::Error::custom(
        "invalid nonce, all zeros or all ones",
    ))
}

#[cfg(test)]
mod tests {
    // the prefixed base64 logic is all quickcheck tested in base64_helper, so
    // this is just some basic sanity checking

    use super::*;

    #[test]
    fn client_rt() {
        let client_nonce = ClientNonce(Nonce([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 0, 1,
        ]));

        let ser = serde_json::to_string(&client_nonce).unwrap();
        assert!(ser.starts_with("\"c!"));

        assert_eq!(client_nonce, serde_json::from_str(&ser).unwrap());
        assert!(serde_json::from_str::<ServerNonce>(&ser).is_err());
    }

    #[test]
    fn server_rt() {
        let server_nonce = ServerNonce(Nonce([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 0, 1,
        ]));

        let ser = serde_json::to_string(&server_nonce).unwrap();
        assert!(ser.starts_with("\"s!"));

        assert_eq!(server_nonce, serde_json::from_str(&ser).unwrap());
        assert!(serde_json::from_str::<ClientNonce>(&ser).is_err());
    }

    #[test]
    fn no_all_zero() {
        macro_rules! bad_nonce_doesnt_roundtrip {
            ($t:ty, $d:expr) => {
                let n = $d;
                let ser = serde_json::to_string(&n).unwrap();
                assert!(serde_json::from_str::<$t>(&ser).is_err());
            };
        }
        bad_nonce_doesnt_roundtrip!(ClientNonce, ClientNonce(Nonce([0; 32])));
        bad_nonce_doesnt_roundtrip!(ClientNonce, ClientNonce(Nonce([1; 32])));
        bad_nonce_doesnt_roundtrip!(ServerNonce, ServerNonce(Nonce([0; 32])));
        bad_nonce_doesnt_roundtrip!(ServerNonce, ServerNonce(Nonce([1; 32])));
    }
}
