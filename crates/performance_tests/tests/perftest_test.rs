#![cfg(feature = "run_system_tests")]
// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use goose::config::GooseConfiguration;
use goose::prelude::*;

use performance_tests::loadtest::scenario::*;
use performance_tests::shared::types::HashCount;
use reqwest::Url;
use std::str::FromStr;

const CLIENT_ENDPOINT: &str = "http://localhost:80";
const KEYSERVER_ENDPOINT: &str = "http://localhost:5301";
const HDBSERVER_ENDPOINT: &str = "http://localhost:5300";

async fn execute_transaction(url: Url, transaction: Transaction) -> TransactionResult {
    let mut conf = GooseConfiguration::default();
    conf.co_mitigation = Some(GooseCoordinatedOmissionMitigation::Disabled);

    let mut user = GooseUser::single(url, &conf).unwrap();

    let function = &transaction.function;

    function(&mut user).await
}

#[tokio::test]
async fn test_random_sequence() {
    let client = Url::from_str(CLIENT_ENDPOINT).unwrap();

    execute_transaction(client, random_sequence(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_single_organism_permutations() {
    let client = Url::from_str(CLIENT_ENDPOINT).unwrap();

    execute_transaction(client, single_organism_permutations(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_single_known_organism() {
    let client = Url::from_str(CLIENT_ENDPOINT).unwrap();

    execute_transaction(client, single_known_organism(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "broken with SCEP changes"]
async fn test_ks_random_bytes() {
    let client = Url::from_str(KEYSERVER_ENDPOINT).unwrap();

    execute_transaction(client, ks_random_bytes_v4(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "broken with SCEP changes"]
async fn test_ks_repeat_bytes() {
    let client = Url::from_str(KEYSERVER_ENDPOINT).unwrap();

    execute_transaction(client, ks_repeat_bytes_v4(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "broken with SCEP changes"]
async fn test_hdb_random_bytes() {
    let client = Url::from_str(HDBSERVER_ENDPOINT).unwrap();

    execute_transaction(client, hdb_random_bytes_v4(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "broken with SCEP changes"]
async fn test_hdb_repeat_bytes() {
    let client = Url::from_str(HDBSERVER_ENDPOINT).unwrap();

    execute_transaction(client, hdb_repeat_bytes_v4(HashCount(32)))
        .await
        .unwrap();
}
