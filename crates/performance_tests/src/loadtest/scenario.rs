// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use doprf::tagged::TaggedHash;
use goose::goose::{GooseMethod, GooseRequest, GooseUser, TransactionError, TransactionResult};
use goose::logger::GooseLog;
use goose::metrics::{GooseMetric, GooseRequestMetric};
use goose::prelude::Transaction;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{header::CONTENT_TYPE, Body};

use doprf::prf::{CompletedHashValue, Query};
use packed_ristretto::datatype::HTTP_MIME_TYPE as PACKED_RISTRETTO_MIME_TYPE;
use streamed_ristretto::HasContentType;

const JSON_MIME_TYPE: &str = "application/json";
const QUERYSET_MIME_TYPE: &str = "application/x-hdb-queryset";

use crate::loadtest::request::{
    get_flat_random_byte_array, get_random_packed_ristretto, get_tagged_random_byte_array,
    screen_payload_builder, single_known_hazard_const_len, single_random_perm_const_len,
    single_random_sequence_of_size,
};
use crate::shared::types::HashCount;

fn post<F, B>(path: &'static str, headers: HeaderMap, generate_body: F) -> Transaction
where
    F: Fn() -> B + Clone + Send + Sync + 'static,
    B: Into<Body> + Send,
{
    Transaction::new(Arc::new(move |user: &mut GooseUser| {
        let generate_body = generate_body.clone();
        let headers = headers.clone();
        Box::pin(async move {
            let request_builder = user
                .get_request_builder(&GooseMethod::Post, path)?
                .headers(headers)
                .body(generate_body());
            let goose_request = GooseRequest::builder()
                .set_request_builder(request_builder)
                .build();

            // WARNING this is pretty hacky
            // Goose has no way of including the download of the payload time in the response times.
            // We do not want to fork it, and it this somehow magically works.
            // If `no_metrics` is set, no metrics will be send to the metrics channel via send_request_metric_to_parent
            // and we can do it manually after we have calculated our own times including the payload download

            user.config.no_metrics = true;
            let started = Instant::now();
            let mut goose_response = user.request(goose_request).await.map_err(|e| {
                user.config.no_metrics = false;
                e
            })?;

            user.config.no_metrics = false;

            let reqwest_response = goose_response.response.map_err(TransactionError::Reqwest)?;

            let status = reqwest_response.status();
            let headers = reqwest_response.headers().clone();

            // Force goose to download the full response instead of cutting the connection
            // as soon as it gets the response headers.
            let text = reqwest_response.text().await;

            // only measure the response time after we have downloaded the body
            goose_response.request.response_time = started.elapsed().as_millis() as u64;

            // as of Goose 0.17.1 set_success and set_failure wont send metrics again,
            // they just count the nr of successes and failures
            let tx_result = if status.is_success() {
                user.set_success(&mut goose_response.request)
            } else {
                user.set_failure(
                    text.as_deref().unwrap_or("empty response"),
                    &mut goose_response.request,
                    Some(&headers),
                    None,
                )
            };

            goose_hack_send_request_metric_to_parent(user, goose_response.request)?;

            tx_result
        })
    }))
}

/// This function is a copy of the private function `send_request_metric_to_parent` in goose.rs
fn goose_hack_send_request_metric_to_parent(
    user: &mut GooseUser,
    request_metric: GooseRequestMetric,
) -> TransactionResult {
    // If requests-file is enabled, send a copy of the raw request to the logger thread.
    if !user.config.request_log.is_empty() {
        if let Some(logger) = user.logger.as_ref() {
            if let Err(e) = logger.send(Some(GooseLog::Request(request_metric.clone()))) {
                return Err(Box::new(e.into()));
            }
        }
    }

    if let Some(metrics_channel) = user.metrics_channel.clone() {
        if let Err(e) = metrics_channel.send(GooseMetric::Request(Box::new(request_metric))) {
            return Err(Box::new(e.into()));
        }
    }

    Ok(())
}

pub fn ks_random_bytes_v1(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(QUERYSET_MIME_TYPE));
    post("hash", headers, move || {
        get_flat_random_byte_array(hash_count.0)
    })
}

pub fn ks_random_bytes_v2(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(PACKED_RISTRETTO_MIME_TYPE),
    );
    post("v2/hash", headers, move || {
        get_random_packed_ristretto::<Query>(hash_count.0).serialize()
    })
}

pub fn ks_random_bytes_v3(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(PACKED_RISTRETTO_MIME_TYPE),
    );
    post("v3/hash", headers, move || {
        get_random_packed_ristretto::<Query>(hash_count.0).serialize()
    })
}

pub fn ks_random_bytes_v4(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(Query::CONTENT_TYPE));
    post("v4/hash", headers, move || {
        get_flat_random_byte_array(hash_count.0)
    })
}

pub fn ks_repeat_bytes_v1(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(QUERYSET_MIME_TYPE));
    let payload: Bytes = get_flat_random_byte_array(hash_count.0).into();
    post("hash", headers, move || payload.clone())
}

pub fn ks_repeat_bytes_v2(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(PACKED_RISTRETTO_MIME_TYPE),
    );
    let payload: Bytes = get_random_packed_ristretto::<Query>(hash_count.0)
        .serialize()
        .into();
    post("v2/hash", headers, move || payload.clone())
}

pub fn ks_repeat_bytes_v3(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(PACKED_RISTRETTO_MIME_TYPE),
    );
    let payload: Bytes = get_random_packed_ristretto::<Query>(hash_count.0)
        .serialize()
        .into();
    post("v3/hash", headers, move || payload.clone())
}

pub fn ks_repeat_bytes_v4(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(Query::CONTENT_TYPE));

    let payload: Bytes = get_flat_random_byte_array(hash_count.0).into();
    post("v4/hash", headers, move || payload.clone())
}

pub fn hdb_random_bytes_v1(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(QUERYSET_MIME_TYPE));
    post("q", headers, move || {
        get_flat_random_byte_array(hash_count.0)
    })
}

pub fn hdb_random_bytes_v2(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(PACKED_RISTRETTO_MIME_TYPE),
    );
    post("v2/q", headers, move || {
        get_random_packed_ristretto::<CompletedHashValue>(hash_count.0).serialize()
    })
}

pub fn hdb_random_bytes_v3(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(Query::CONTENT_TYPE));
    post("v3/q", headers, move || {
        get_random_packed_ristretto::<CompletedHashValue>(hash_count.0).serialize()
    })
}

pub fn hdb_random_bytes_v4(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(TaggedHash::CONTENT_TYPE),
    );
    post("v4/q", headers, move || {
        get_tagged_random_byte_array(hash_count.0)
    })
}

pub fn hdb_repeat_bytes_v1(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(QUERYSET_MIME_TYPE));
    let payload: Bytes = get_flat_random_byte_array(hash_count.0).into();
    post("q", headers, move || payload.clone())
}

pub fn hdb_repeat_bytes_v2(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(PACKED_RISTRETTO_MIME_TYPE),
    );
    let payload: Bytes = get_random_packed_ristretto::<CompletedHashValue>(hash_count.0)
        .serialize()
        .into();
    post("v2/q", headers, move || payload.clone())
}

pub fn hdb_repeat_bytes_v3(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(PACKED_RISTRETTO_MIME_TYPE),
    );
    let payload: Bytes = get_random_packed_ristretto::<CompletedHashValue>(hash_count.0)
        .serialize()
        .into();
    post("v3/q", headers, move || payload.clone())
}

pub fn hdb_repeat_bytes_v4(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(TaggedHash::CONTENT_TYPE),
    );
    let payload: Bytes = get_tagged_random_byte_array(hash_count.0).into();
    post("v4/q", headers, move || payload.clone())
}

pub fn single_organism_permutations(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(JSON_MIME_TYPE));
    post("v1/screen", headers, move || {
        screen_payload_builder(single_random_perm_const_len(hash_count.to_bp_count().0).as_str())
    })
}

pub fn single_known_organism(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(JSON_MIME_TYPE));
    post("v1/screen", headers, move || {
        screen_payload_builder(single_known_hazard_const_len(hash_count.to_bp_count().0).as_str())
    })
}

pub fn random_sequence(hash_count: HashCount) -> Transaction {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static(JSON_MIME_TYPE));
    post("v1/screen", headers, move || {
        screen_payload_builder(single_random_sequence_of_size(hash_count.to_bp_count().0).as_str())
    })
}

pub fn unimplemented_scenario() -> Transaction {
    unimplemented!();
}
