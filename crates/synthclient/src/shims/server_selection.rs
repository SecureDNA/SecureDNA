// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use doprf_client::server_selection::{ServerSelectionConfig, ServerSelectionError, ServerSelector};
use http_client::{BaseApiClient, HttpsToHttpRewriter};
use shared_types::{info_with_timestamp, requests::RequestId};

use crate::retry_if;

use super::types::{Opts, SelectionRefreshArgs};

pub async fn initialize_server_selector(
    opts: &Opts,
) -> Result<ServerSelector, ServerSelectionError> {
    retry_if::retry_if(
        || async {
            let SelectionRefreshArgs {
                soft_timeout,
                blocking_timeout,
                soft_extra_keyserver_threshold,
                soft_extra_hdb_threshold,
            } = opts.selection_refresh;

            let soft_extra_keyserver_threshold = match soft_extra_keyserver_threshold {
                0 => None,
                n => Some(n),
            };
            let soft_extra_hdb_threshold = match soft_extra_hdb_threshold {
                0 => None,
                n => Some(n),
            };
            ServerSelector::new(
                ServerSelectionConfig {
                    enumeration_source: opts.enumeration.validate_and_build(),
                    soft_timeout: Some(soft_timeout.into()),
                    blocking_timeout: Some(blocking_timeout.into()),
                    soft_extra_keyserver_threshold,
                    soft_extra_hdb_threshold,
                },
                {
                    let client =
                        BaseApiClient::new(RequestId::new_unique_with_prefix("server-selection"));
                    if opts.use_http {
                        HttpsToHttpRewriter::inject(client)
                    } else {
                        client
                    }
                },
            )
            .await
        },
        |e| {
            info_with_timestamp!("Attempt to initialize server selector failed: {}", e);
            true
        },
    )
    .await
}
