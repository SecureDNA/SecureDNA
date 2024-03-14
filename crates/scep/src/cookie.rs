// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fmt, str::FromStr};

use cookie::{Cookie, SameSite};
use rand::distributions::{Distribution, Standard};

#[derive(Clone, Copy, PartialEq, Eq, std::hash::Hash)]
pub struct SessionCookie([u8; 32]);

impl SessionCookie {
    /// Build a `Cookie` from this session cookie
    /// If `allow_insecure` is `true`, the `secure` flag won't be set on the cookie,
    /// allowing it to be transported over http://. This is useful for local testing.
    pub fn to_http_cookie(&self, allow_insecure: bool) -> Cookie {
        Cookie::build(("SecureDNA".to_owned(), self.to_string()))
            .secure(!allow_insecure)
            .http_only(true)
            .same_site(SameSite::Strict)
            .build()
    }
}

impl fmt::Display for SessionCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0u8; 64];
        // neither of these unwraps can fail
        hex::encode_to_slice(self.0, &mut bytes).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        f.write_str(s)
    }
}

impl fmt::Debug for SessionCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionCookie")
            .field(&self.to_string())
            .finish()
    }
}

impl FromStr for SessionCookie {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Distribution<SessionCookie> for Standard {
    fn sample<R: rand::prelude::Rng + ?Sized>(&self, rng: &mut R) -> SessionCookie {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        SessionCookie(bytes)
    }
}
