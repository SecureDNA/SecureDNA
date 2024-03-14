// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use anyhow::Context;
use futures::{StreamExt, TryStreamExt};
use hyper::body::{Body, Incoming};
use hyper::{Request, StatusCode};
use tracing::{error, info, warn};

use doprf::tagged::{HashTag, TaggedHash};
use hdb::consolidate_windows::{consolidate_windows, HashId};
use hdb::{self, Exemptions, HdbConfig, HdbParams};
use minhttp::response::{self, GenericResponse};
use scep::error::ScepError;
use scep::types::ScreenCommon;
use shared_types::hdb::HdbScreeningResult;
use shared_types::requests::RequestId;
use streamed_ristretto::hyper::{check_content_length, from_request};
use streamed_ristretto::stream::{check_content_type, ShortErrorMsg, StreamableRistretto};
use streamed_ristretto::HasContentType;

use crate::event_store;
use crate::state::HdbServerState;

struct UnparsedTaggedHash([u8; TaggedHash::SIZE]);

impl UnparsedTaggedHash {
    fn hash_tag(&self) -> HashTag {
        HashTag::from_bytes(self.0[..4].try_into().unwrap())
    }
    fn hash_bytes(&self) -> &[u8; 32] {
        self.0[4..].try_into().unwrap()
    }
}

impl HasContentType for UnparsedTaggedHash {
    const CONTENT_TYPE: &'static str = TaggedHash::CONTENT_TYPE;
}

impl From<[u8; TaggedHash::SIZE]> for UnparsedTaggedHash {
    fn from(bytes: [u8; TaggedHash::SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<UnparsedTaggedHash> for [u8; TaggedHash::SIZE] {
    fn from(hash: UnparsedTaggedHash) -> Self {
        hash.0
    }
}

impl StreamableRistretto for UnparsedTaggedHash {
    type Array = [u8; TaggedHash::SIZE];
    type ConversionError = <Self::Array as TryInto<Self>>::Error;

    fn fit_error(error: &ShortErrorMsg) -> Self::Array {
        let mut data = [255; TaggedHash::SIZE];
        data[4 + 1..TaggedHash::SIZE - 1].copy_from_slice(error);
        data
    }
}

pub async fn scep_endpoint_screen(
    request_id: &RequestId,
    hdbs_state: Arc<HdbServerState>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::Screen>> {
    check_content_type(request.headers(), TaggedHash::CONTENT_TYPE)
        .context("in screen")
        .map_err(scep::error::ScepError::InvalidMessage)?;

    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = hdbs_state
        .scep
        .clients
        .write()
        .await
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let hash_count_from_content_len =
        check_content_length(request.body().size_hint().exact(), TaggedHash::SIZE)
            .context("in screen")
            .map_err(scep::error::ScepError::InvalidMessage)?;

    let (params, client_state) =
        scep::steps::server_screen_client(hash_count_from_content_len, client_state)?;

    let ScreenCommon {
        region,
        provider_reference,
    } = params;

    let permit = match hdbs_state.throttle_heavy_requests() {
        Ok(permit) => permit,
        Err(err_response) => return Ok(err_response),
    };

    let screen_evt_id = match event_store::insert_screen_event(
        &hdbs_state.persistence_connection,
        client_state.open_request.client_mid(),
        client_state.open_request.nucleotide_total_count,
        region,
    )
    .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            error!(
                "Failed to persist screen event for {}: {e}",
                client_state.open_request.client_mid()
            );
            None
        }
    };

    // make empty exemptions for non-EL screening
    let exemptions = Arc::new(Exemptions::default());

    if let Some(metrics) = &hdbs_state.metrics {
        metrics.requests.inc();
    }

    let num_hashes = check_content_length(request.body().size_hint().exact(), TaggedHash::SIZE)
        .context("in screen")
        .map_err(ScepError::InvalidMessage)?;
    info!("{request_id}: Processing request of size {num_hashes}");

    let queries = from_request(request)
        .context("in screen")
        .map_err(ScepError::InvalidMessage)?;

    struct LogDone(RequestId);

    impl Drop for LogDone {
        fn drop(&mut self) {
            info!("{}: Done.", self.0);
        }
    }

    let logdone = LogDone(request_id.clone());

    let mut last_record = None;
    let hdbs_state2 = hdbs_state.clone();
    let exemptions2 = exemptions.clone();
    let hdb_responses: Result<Vec<_>, anyhow::Error> = queries
        .map(move |query| {
            let _permit = &permit;
            let _logdone = &logdone;

            let hash_id_and_query = query.map(|query: UnparsedTaggedHash| {
                let hash_id = HashId::new(query.hash_tag(), last_record);
                last_record = Some(hash_id.record);
                (hash_id, query)
            });

            let hdbs_state2 = hdbs_state2.clone();
            let exemptions2 = exemptions2.clone();
            async move {
                let (hash_id, query) = hash_id_and_query?;

                let permit = hdbs_state2
                    .hdb_queries
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap();
                // TODO: Maybe use a nursery to prevent orphans, so long as that's not too expensive?
                let hdbs_state3 = hdbs_state2.clone();
                let exemptions3 = exemptions2.clone();
                let resp = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let params = HdbParams {
                        region,
                        exemptions: &exemptions3,
                    };
                    let config = HdbConfig {
                        database: &hdbs_state3.database,
                        hlt: &hdbs_state3.hlt,
                    };
                    hdb::query_hdb(query.hash_bytes(), &params, &config)
                })
                .await
                .unwrap()?;

                // only incremented if there's no error
                if let Some(metrics) = &hdbs_state2.metrics {
                    metrics.hash_counter.inc();
                }

                Ok(resp.map(|r| (hash_id, r)))
            }
        })
        .buffered(hdbs_state.parallelism_per_request)
        .filter_map(|res| async { res.transpose() })
        .try_collect()
        .await;

    let hdb_responses = match hdb_responses {
        Ok(r) => r,
        Err(err) => {
            warn!("Error while processing HDB records: {err:?}");
            if let Some(metrics) = &hdbs_state.metrics {
                metrics.io_errors.inc();
            }
            return Ok(response::text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error",
            ));
        }
    };

    let consolidation =
        consolidate_windows(hdb_responses.into_iter(), &hdbs_state.hash_spec, false)
            .context("in screen consolidation")
            .map_err(ScepError::InternalError)?;

    let response: HdbScreeningResult = consolidation.to_hdb_screening_result(provider_reference);

    if let Some(screen_evt_id) = screen_evt_id {
        if let Err(e) = event_store::insert_screen_result(
            &hdbs_state.persistence_connection,
            screen_evt_id,
            shared_types::synthesis_permission::SynthesisPermission::merge(
                response.results.iter().map(|r| r.synthesis_permission),
            ),
        )
        .await
        {
            error!(
                "Failed to persist screening result for {}: {e}",
                client_state.open_request.client_mid()
            );
        }
    }

    let json = serde_json::to_string(&response)
        .context("in screen serialization")
        .map_err(ScepError::InternalError)?;

    Ok(response::json(StatusCode::OK, json))
}
