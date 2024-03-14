// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::{Request, StatusCode};
use tracing::warn;

use minhttp::response::{self, ErrResponse, ResponseResult};
use shared_types::server_selection::{HdbQualificationResponse, QualificationRequest};
use streamed_ristretto::stream::MessageError;

use crate::state::HdbServerState;

pub async fn qualification(
    hdbs_state: &HdbServerState,
    request: Request<Incoming>,
) -> ResponseResult {
    let body = match request.body().size_hint().exact() {
        Some(size) if size < hdbs_state.scep.json_size_limit => request
            .into_body()
            .collect()
            .await
            .map_err(|e| ErrResponse(response::text(StatusCode::INTERNAL_SERVER_ERROR, e)))?
            .to_bytes(),
        size => {
            return Err(ErrResponse(response::text(
                StatusCode::BAD_REQUEST,
                MessageError::InvalidContentLength(size),
            )))
        }
    };

    let data: QualificationRequest = serde_json::from_slice(&body)
        .map_err(|e| ErrResponse(response::text(StatusCode::BAD_REQUEST, e)))?;

    if data.client_version != 0 {
        return Err(ErrResponse(response::text(
            StatusCode::BAD_REQUEST,
            "bad client version",
        )));
    }

    let response = HdbQualificationResponse {
        supported_generations: vec![0],
    };

    let json = serde_json::to_string(&response).map_err(|err| {
        warn!("failed to serialize qualification response: {err}");
        ErrResponse(response::text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error",
        ))
    })?;
    Ok(response::json(StatusCode::OK, json))
}
