#![cfg(feature = "run_system_tests")]
// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env::VarError;

use goose::config::GooseConfiguration;
use goose::prelude::*;
use reqwest::Url;

use performance_tests::loadtest::scenario::*;
use performance_tests::shared::types::HashCount;

fn get_env(var: &str, fallback: &str) -> Url {
    match std::env::var(var) {
        Ok(var) => var.parse().unwrap(),
        Err(VarError::NotPresent) => fallback.parse().unwrap(),
        Err(VarError::NotUnicode(_)) => panic!("{var} wasn't unicode"),
    }
}

fn client_endpoint() -> Url {
    get_env("SDNA_SYS_TEST_SC_URL", "http://localhost:80")
}

fn keyserver_endpoint() -> Url {
    get_env("SDNA_SYS_TEST_KS_URL", "http://localhost:5301")
}

fn hdbserver_endpoint() -> Url {
    get_env("SDNA_SYS_TEST_HDB_URL", "http://localhost:5300")
}

async fn execute_transaction(url: Url, transaction: Transaction) -> TransactionResult {
    let mut conf = GooseConfiguration::default();
    conf.co_mitigation = Some(GooseCoordinatedOmissionMitigation::Disabled);

    let mut user = GooseUser::single(url, &conf).unwrap();

    let function = &transaction.function;

    function(&mut user).await
}

#[tokio::test]
async fn test_random_sequence() {
    let client = client_endpoint();

    execute_transaction(client, random_sequence(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_single_organism_permutations() {
    let client = client_endpoint();

    execute_transaction(client, single_organism_permutations(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_single_known_organism() {
    let client = client_endpoint();

    execute_transaction(client, single_known_organism(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "broken with SCEP changes"]
async fn test_ks_random_bytes() {
    let client = keyserver_endpoint();

    execute_transaction(client, ks_random_bytes_v4(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "broken with SCEP changes"]
async fn test_ks_repeat_bytes() {
    let client = keyserver_endpoint();

    execute_transaction(client, ks_repeat_bytes_v4(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "broken with SCEP changes"]
async fn test_hdb_random_bytes() {
    let client = hdbserver_endpoint();

    execute_transaction(client, hdb_random_bytes_v4(HashCount(32)))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "broken with SCEP changes"]
async fn test_hdb_repeat_bytes() {
    let client = hdbserver_endpoint();

    execute_transaction(client, hdb_repeat_bytes_v4(HashCount(32)))
        .await
        .unwrap();
}
