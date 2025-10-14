// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fmt, str::FromStr};

use cookie::{Cookie, SameSite};
use http::{HeaderMap, HeaderName, HeaderValue};
use rand::distributions::{Distribution, Standard};

use crate::error::ScepError;

#[derive(Clone, Copy, PartialEq, Eq, std::hash::Hash)]
pub struct SessionCookie([u8; 32]);

impl SessionCookie {
    const COOKIE_NAME: &'static str = "SecureDNA";
    const HEADER: HeaderName = HeaderName::from_static("securedna-session-id");

    /// Build a `Cookie` from this session cookie
    /// If `allow_insecure` is `true`, the `secure` flag won't be set on the cookie,
    /// allowing it to be transported over http://. This is useful for local testing.
    ///
    /// This should only be used by v1 SCEP.
    pub fn to_http_cookie(&self, allow_insecure: bool) -> Cookie {
        Cookie::build((Self::COOKIE_NAME.to_owned(), self.to_string()))
            .secure(!allow_insecure)
            .http_only(true)
            .same_site(SameSite::Strict)
            .build()
    }

    /// Return a header name/value pair representing this session ID.
    pub fn to_http_header(&self) -> (HeaderName, HeaderValue) {
        let base64_session = crate::base64::encode(self.0)
            .try_into()
            .expect("HTTP headers can hold base64 values");
        (Self::HEADER, base64_session)
    }

    /// Try to get the SCEP session cookie from Cookie: ... headers, returning `ScepError::InvalidMessage` if
    /// there are none, multiple, or the format is incorrect.
    pub fn from_request_http_headers<E>(headers: &HeaderMap) -> Result<Self, ScepError<E>>
    where
        E: std::error::Error,
    {
        let header_sessions = headers
            .get_all(Self::HEADER)
            .into_iter()
            .filter_map(|header| {
                let bytes = crate::base64::decode_array(header).ok()?;
                Some(Self(bytes))
            });

        let cookie_sessions = headers
            .get_all(http::header::COOKIE)
            .into_iter()
            .filter_map(|cookie| {
                let cookie = cookie.to_str().ok()?;
                let cookie = cookie::Cookie::parse(cookie).ok()?;
                if cookie.name() != Self::COOKIE_NAME {
                    None
                } else {
                    Some(cookie.value().parse().ok()?)
                }
            });

        let mut sessions = header_sessions.chain(cookie_sessions);
        match (sessions.next(), sessions.next()) {
            (Some(session), None) => Ok(session),
            (Some(_), Some(_)) => Err(ScepError::InvalidMessage(anyhow::anyhow!(
                "multiple valid sessions"
            ))),
            (None, _) => Err(ScepError::InvalidMessage(anyhow::anyhow!(
                "missing or invalid session"
            ))),
        }
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
        SessionCookie(rng.gen())
    }
}

impl AsRef<[u8]> for SessionCookie {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for SessionCookie {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        base64_helper::serialize(serializer, crate::base64::B64, &self.0)
    }
}

impl<'de> serde::Deserialize<'de> for SessionCookie {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        base64_helper::deserialize(deserializer, crate::base64::B64).map(SessionCookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;

    use quickcheck::{quickcheck, Arbitrary, Gen};
    use rand::Rng;

    impl Arbitrary for SessionCookie {
        fn arbitrary(g: &mut Gen) -> Self {
            SessionCookie(core::array::from_fn(|_| Arbitrary::arbitrary(g)))
        }
    }

    quickcheck! {
        fn roundtrips_string(sc: SessionCookie) -> bool {
            let s = sc.to_string();
            SessionCookie::from_str(&s).unwrap() == sc
        }

        fn roundtrips_http_cookie(sc: SessionCookie, secure: bool) -> bool {
            let cookie = sc.to_http_cookie(secure);
            SessionCookie::from_str(cookie.value()).unwrap() == sc
        }

        fn roundtrips_http_header(sc: SessionCookie) -> bool {
            let headers = HeaderMap::from_iter([sc.to_http_header()]);
            SessionCookie::from_request_http_headers::<Infallible>(&headers).unwrap() == sc
        }
    }

    #[test]
    fn test_header_extraction() {
        let cookie: SessionCookie = rand::thread_rng().gen();
        let headers = HeaderMap::from_iter([(
            http::header::COOKIE,
            cookie.to_http_cookie(false).to_string().parse().unwrap(),
        )]);

        assert_eq!(
            cookie,
            SessionCookie::from_request_http_headers::<Infallible>(&headers).unwrap()
        );
    }

    #[test]
    fn test_header_missing() {
        let e =
            SessionCookie::from_request_http_headers::<Infallible>(&HeaderMap::new()).unwrap_err();
        assert!(
            matches!(
                &e,
                ScepError::InvalidMessage(s) if s.to_string().contains("missing or invalid")
            ),
            "{e}"
        );
    }

    #[test]
    fn test_header_invalid() {
        let session: SessionCookie = rand::thread_rng().gen();
        let (header, _) = session.to_http_header();
        let value = HeaderValue::from_static("foobar");

        let headers = HeaderMap::from_iter([(header, value)]);

        let e = SessionCookie::from_request_http_headers::<Infallible>(&headers).unwrap_err();
        assert!(
            matches!(
                &e,
                ScepError::InvalidMessage(s) if s.to_string().contains("missing or invalid")
            ),
            "{e}"
        );
    }

    #[test]
    fn test_cookie_invalid() {
        let session: SessionCookie = rand::thread_rng().gen();
        let mut cookie = session.to_http_cookie(false);
        cookie.set_value("foobar");

        let headers =
            HeaderMap::from_iter([(http::header::COOKIE, cookie.to_string().parse().unwrap())]);

        let e = SessionCookie::from_request_http_headers::<Infallible>(&headers).unwrap_err();
        assert!(
            matches!(
                &e,
                ScepError::InvalidMessage(s) if s.to_string().contains("missing or invalid")
            ),
            "{e}"
        );
    }

    #[test]
    fn test_header_multiple() {
        let session: SessionCookie = rand::thread_rng().gen();

        let header = session.to_http_header();
        let headers = HeaderMap::from_iter([header.clone(), header.clone()]);

        let e = SessionCookie::from_request_http_headers::<Infallible>(&headers).unwrap_err();
        assert!(
            matches!(
                &e,
                ScepError::InvalidMessage(s) if s.to_string().contains("multiple")
            ),
            "{e}"
        );
    }

    #[test]
    fn test_cookie_multiple() {
        let session: SessionCookie = rand::thread_rng().gen();
        let cookie = session.to_http_cookie(false);

        let header = (http::header::COOKIE, cookie.to_string().parse().unwrap());
        let headers = HeaderMap::from_iter([header.clone(), header.clone()]);

        let e = SessionCookie::from_request_http_headers::<Infallible>(&headers).unwrap_err();
        assert!(
            matches!(
                &e,
                ScepError::InvalidMessage(s) if s.to_string().contains("multiple")
            ),
            "{e}"
        );
    }
}
