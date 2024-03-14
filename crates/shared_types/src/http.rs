// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use http::{header, HeaderMap, HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::requests::RequestId;

impl From<&HeaderMap> for RequestId {
    fn from(headers: &HeaderMap) -> Self {
        let mut req_ids = headers.get_all(Self::FIELD).iter();
        req_ids
            .next()
            .filter(|_| req_ids.next().is_none())
            .and_then(|r_id| Self::from_bytes(r_id.as_bytes()).ok())
            .unwrap_or(Self::unknown())
    }
}

const BASE_CORS_HEADERS: [(&str, &str); 3] = [
    // ("access-control-allow-origin", "*"),
    ("access-control-allow-methods", "POST, GET, PATCH, OPTIONS"),
    (
        "access-control-allow-headers",
        "Accept, Accept-Encoding, Content-Type, Origin, X-Request-Id, X-Real-Ip, Host, Forwarded, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Protocol, X-Url-Scheme, X-Forwarded-Ssl, Front-End-Https",
    ),
    ("access-control-allow-credentials", "true"),
];

/// If the `Origin` of the given `request_headers` is trusted (*.securedna.org),
/// add appropriate CORS headers to `response_headers`, mirroring the Origin in the
/// `Access-Control-Allow-Origin` header. Otherwise, do nothing.
pub fn add_cors_headers(request_headers: &HeaderMap, response_headers: &mut HeaderMap) {
    if let Some(origin) = request_headers.get("origin") {
        if is_trusted_origin(origin.as_bytes()) {
            response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
            for (header, value) in BASE_CORS_HEADERS {
                response_headers.insert(
                    HeaderName::from_static(header),
                    HeaderValue::from_static(value),
                );
            }
        }
    }
}

fn is_trusted_origin(origin: &[u8]) -> bool {
    static ORIGIN_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^https?://(localhost|127\.0\.0\.1|(\w+\.)*securedna.org)(:\d+)?$").unwrap()
    });
    ORIGIN_REGEX.is_match(origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_add_cors_headers() {
        let mut request_headers = http::HeaderMap::new();
        request_headers.insert(
            http::header::ORIGIN,
            http::HeaderValue::from_static("https://test.securedna.org"),
        );
        let mut headers = http::HeaderMap::new();
        // This will at least catch panics due to the http crate rejecting non-canonical HeaderNames
        add_cors_headers(&request_headers, &mut headers);
        assert!(!headers.is_empty());
    }

    #[test]
    fn test_is_trusted_origin() {
        assert!(is_trusted_origin(b"http://localhost"));
        assert!(is_trusted_origin(b"http://localhost:1234"));
        assert!(is_trusted_origin(b"http://securedna.org"));
        assert!(is_trusted_origin(b"https://securedna.org"));
        assert!(is_trusted_origin(b"http://subdomain.securedna.org"));
        assert!(is_trusted_origin(b"https://foo.securedna.org"));
        assert!(is_trusted_origin(b"http://securedna.org:8000"));
        assert!(is_trusted_origin(b"https://securedna.org:8000"));
        assert!(is_trusted_origin(b"http://pages.securedna.org:8000"));
        assert!(is_trusted_origin(b"https://ks1.localhost.securedna.org"));

        assert!(!is_trusted_origin(b"http://localho.st"));
        assert!(!is_trusted_origin(b"https://notsecuredna.org"));
        assert!(!is_trusted_origin(b"https://securedna.example.org"));
        assert!(!is_trusted_origin(b"https://securedna.example.org:8000"));
        assert!(!is_trusted_origin(b"https://securedna.com"));
        assert!(!is_trusted_origin(b"https://securedna.com:8000"));
    }
}
