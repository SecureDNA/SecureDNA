// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use anyhow::Context;
use bytes::{Buf, Bytes, BytesMut};

use futures::stream::iter as to_stream;
use futures::{StreamExt, TryStream, TryStreamExt};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Request, Response};
use tracing::info;

use doprf::prf::{HashPart, Query};
use minhttp::response::GenericResponse;
use shared_types::requests::RequestId;
use streamed_ristretto::hyper::{check_content_length, BodyStream};
use streamed_ristretto::stream::{
    check_content_type, ConversionError, HasShortErrorMsg, RistrettoError, HASH_SIZE,
};
use streamed_ristretto::util::chunked;
use streamed_ristretto::HasContentType;

use crate::state::KeyserverState;

// Given a stream of `Bytes`/errors, interprets them as `Queries` and applies `f` to them
//
// Encodes the resulting `HashPart`s back into Bytes and returns a stream of said `Bytes`/errors.
fn map_ristretto_stream<I, P>(
    ks_state: &Arc<KeyserverState>,
    heavy_request_permit: P,
    input: I,
    f: impl FnMut(Query) -> HashPart + Clone + Send + 'static,
) -> impl TryStream<Ok = Bytes, Error = RistrettoError<I::Error, ConversionError<Query>>>
where
    I: TryStream,
    I::Ok: Buf,
    I::Error: Send + 'static,
{
    let mut output_bufs = BytesMut::new();
    let ks_state2 = ks_state.clone();
    chunked(input, HASH_SIZE)
        .map(move |chunk| {
            // IMPORTANT: The request continues to be processed AFTER the outer function returns
            // so we move `permit` into the closure to keep it until processing finishes.
            let _heavy_request_permit = &heavy_request_permit;

            let chunk = chunk.map_err(RistrettoError::Stream)?;
            if chunk.len() % HASH_SIZE != 0 {
                return Err(RistrettoError::Incomplete { data: chunk });
            }

            // We split off enough memory to hold a mapped chunk
            // so that map_ristretto_chunk doesn't typically need to allocate anything.
            output_bufs.resize(chunk.len(), 0);
            let mut out_buf = output_bufs.split();
            out_buf.truncate(0);

            let f = f.clone();
            let ks_state2 = ks_state2.clone();
            Ok(async move {
                let permit = ks_state2
                    .processing_chunks
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap();

                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    Ok(map_ristretto_chunk(chunk, out_buf, f))
                })
                .await
                .unwrap()
            })
        })
        .try_buffered(ks_state.parallelism_per_request)
        .try_flatten()
        .flat_map(|chunk| match chunk {
            Ok(buf) => {
                let items = [Ok(buf)];
                to_stream(items).left_stream()
            }
            Err(err) => {
                let mut err_data = vec![255; HASH_SIZE];
                err_data[1..HASH_SIZE - 1].copy_from_slice(&err.short_err_msg());
                let items = [Ok(err_data.into()), Err(err)];
                to_stream(items).right_stream()
            }
        })
}

// Decodes `input` into `Queries`, maps them through `f` and returns a stream of `Bytes` / errors.
//
// `output_buf` is used as a buffer to hold encoded `HashParts` before returning them.
fn map_ristretto_chunk<SE>(
    mut input: Bytes,
    mut output_buf: BytesMut,
    mut f: impl FnMut(Query) -> HashPart,
) -> impl TryStream<Ok = Bytes, Error = RistrettoError<SE, ConversionError<Query>>> {
    while !input.is_empty() {
        let data = input.split_to(HASH_SIZE);
        let data_ref: &[u8; HASH_SIZE] = data.as_ref().try_into().unwrap();
        let query = match data_ref.try_into() {
            Ok(q) => q,
            Err(error) => {
                let items = [
                    Ok(output_buf.freeze()),
                    Err(RistrettoError::Conversion { data, error }),
                ];
                return to_stream(items).left_stream();
            }
        };

        let hash_part: [u8; HASH_SIZE] = f(query).into();
        output_buf.extend_from_slice(&hash_part);
    }

    let items = [Ok(output_buf.freeze())];
    to_stream(items).right_stream()
}

pub async fn scep_endpoint_keyserve(
    request_id: &RequestId,
    server_state: &Arc<KeyserverState>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::Keyserve>> {
    check_content_type(request.headers(), Query::CONTENT_TYPE)
        .context("in keyserve")
        .map_err(scep::error::ScepError::InvalidMessage)?;

    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let permit = match server_state.throttle_heavy_requests() {
        Ok(permit) => permit,
        Err(_) => return Err(scep::error::ScepError::Overloaded),
    };

    if let Some(metrics) = &server_state.metrics {
        metrics.requests.inc();
    }

    let client_state = server_state
        .scep
        .clients
        .write()
        .await
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let hash_count_from_content_len =
        check_content_length(request.body().size_hint().exact(), HASH_SIZE)
            .context("in keyserve")
            .map_err(scep::error::ScepError::InvalidMessage)?;

    let keyserver_id_set =
        scep::steps::server_keyserve_client(hash_count_from_content_len, client_state)?;

    info!("{request_id}: Processing request of size {hash_count_from_content_len}");

    let server_state2 = server_state.clone();
    let keyshare = server_state.keyshare;
    let lagrange_coeff = keyserver_id_set.langrange_coefficient_for_id(&server_state.keyserver_id);
    let encrypt_query = move |query| {
        if let Some(metrics) = &server_state2.metrics {
            metrics.hash_counter.inc();
        }
        keyshare.apply_query_and_lagrange_coefficient(query, &lagrange_coeff)
    };

    let chunks = map_ristretto_stream(
        server_state,
        permit,
        BodyStream(request.into_body()),
        encrypt_query,
    );

    let body = StreamBody::new(chunks.map_ok(Frame::data));
    let mut response = Response::new(body);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(HashPart::CONTENT_TYPE),
    );
    let response = response.map(|body| BodyExt::map_err(body, anyhow::Error::from).boxed());
    Ok(response)
}
