// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::SocketAddr;

use tracing::error;

use minhttp::response::{self, StatusCode};
use scep::error::ScepError;
use shared_types::requests::RequestId;

pub fn log_and_convert_scep_error_to_response<Inner>(
    err: &ScepError<Inner>,
    request_id: &RequestId,
    peer: SocketAddr,
) -> minhttp::response::ErrResponse
where
    Inner: std::error::Error,
{
    response::ErrResponse(match err {
        ScepError::BadProtocol => {
            // TODO: we'd ideally cut the connection without a response here, but
            // this is a stopgap
            error!("{request_id}: bad protocol from {peer}");
            response::text(StatusCode::BAD_REQUEST, "bad protocol")
        }
        ScepError::InternalError(e) => {
            error!("{request_id}: internal error: {e}");
            response::text(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
        ScepError::InvalidMessage(e) => response::text(StatusCode::BAD_REQUEST, e),
        ScepError::Overloaded => response::text(
            StatusCode::SERVICE_UNAVAILABLE,
            "server is overloaded. try again later.",
        ),
        ScepError::RateLimitExceeded { limit_bp } => response::text(
            // we don't want to use 429 TOO MANY REQUESTS because we don't want the client to auto-retry,
            // on average it will take 12 hours for this error to resolve.
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("client exceeded daily limit of {limit_bp}bp"),
        ),
        ScepError::Inner(e) => response::text(StatusCode::BAD_REQUEST, e.to_string()),
    })
}
