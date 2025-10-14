// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use tracing::info;

use doprf_client::server_selection::{ServerSelectionConfig, ServerSelectionError, ServerSelector};
use http_client::BaseApiClient;

use crate::retry_if;

use crate::shims::types::Config;

pub async fn initialize_server_selector(
    api_client: BaseApiClient,
    app_cfg: &Config,
) -> Result<ServerSelector, ServerSelectionError> {
    retry_if::retry_if(
        || async {
            let soft_extra_keyserver_threshold =
                match app_cfg.selection_refresh.soft_extra_keyserver_threshold {
                    0 => None,
                    n => Some(n),
                };
            let soft_extra_hdb_threshold = match app_cfg.selection_refresh.soft_extra_hdb_threshold
            {
                0 => None,
                n => Some(n),
            };
            ServerSelector::new(
                ServerSelectionConfig {
                    enumeration_source: app_cfg.enumeration.validate_and_build(),
                    soft_timeout: Some(app_cfg.selection_refresh.soft_timeout.0),
                    blocking_timeout: Some(app_cfg.selection_refresh.blocking_timeout.0),
                    soft_extra_keyserver_threshold,
                    soft_extra_hdb_threshold,
                },
                api_client.clone(),
            )
            .await
        },
        |e| {
            info!("Attempt to initialize server selector failed: {e}");
            true
        },
    )
    .await
}
