// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

/* Configuration Management, we can not use clap here */

use goose::goose::GooseUser;
use goose::prelude::TransactionResult;
use reqwest::header::HeaderMap;
use reqwest::Client;

/* Scenarios and helpers */

pub async fn set_authorized_client(user: &mut GooseUser) -> TransactionResult {
    // TODO: obsolete with SCEP
    let headers = HeaderMap::new();
    set_client(user, headers).await
}

pub async fn set_authorized_client_with_keyserver_ids(user: &mut GooseUser) -> TransactionResult {
    // TODO: obsolete with SCEP
    let headers = HeaderMap::new();
    set_client(user, headers).await
}

async fn set_client(user: &mut GooseUser, headers: HeaderMap) -> TransactionResult {
    let builder = Client::builder().default_headers(headers);
    user.set_client_builder(builder).await?;
    Ok(())
}
