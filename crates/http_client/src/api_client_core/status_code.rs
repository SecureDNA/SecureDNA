// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// If we get the given HTTP status code from KS or HDB during DOPRF, should we
/// backoff and retry?
pub fn is_retriable(code: u16) -> bool {
    match code {
        // Too Many Requests: Well, we might be part of the problem... but
        // hopefully backoff will help.
        429 => true,

        // Internal Server Error: This is a generic response. We might not know
        // what's wrong with the server, so it's worth retrying to check if it's
        // intermittent.
        500 => true,

        // Service Unavailable: Indicates temporary overload or unavailability
        // -- the quintessential "try again later" status code.
        503 => true,

        // Gateway Timeout: We don't know the cause, but a gateway being up
        // whatsoever seems hopeful enough to merit retrying.
        504 => true,

        // Don't retry when we get 400 (Bad Request), 401 (Unauthorized), 404 (Not Found), 501 (Not
        // Implemented)...
        _ => false,
    }
}
