// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use scep_integration_tests::server::{Opts, TestServer};
use shared_types::hash::HashSpec;

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn not_json() {
    let certs = scep_integration_tests::make_certs::make_certs(Default::default());
    let issuer_pks = vec![
        certs.infra_root_keypair.public_key(),
        certs.manu_root_keypair.public_key(),
    ];
    let server = TestServer::spawn(
        Opts {
            issuer_pks,
            server_cert_chain: certs.keyserver_tokenbundle,
            server_keypair: certs.keyserver_keypair,
            keyserve_fn: Arc::new(|_| unreachable!()),
            hash_spec: HashSpec::dna_normal_cech(),
        },
        async {},
    )
    .await;
    let server_port = server.port();

    let http_client = http_client::BaseApiClient::new_external();

    let resp_err = http_client
        .bytes_bytes_post(
            &format!("http://localhost:{server_port}{}", scep::OPEN_ENDPOINT),
            "tea, earl grey, hot".into(),
            "application/json",
            "text/plain",
        )
        .await
        .unwrap_err();

    let http_client::error::HTTPError::RequestError {
        retriable,
        source: error,
        ..
    } = resp_err
    else {
        panic!("Expected RequestError, got {resp_err:?}");
    };

    assert!(!retriable);
    assert!(error.to_string().contains("400 Bad Request"));
    assert!(error.to_string().contains("bad protocol"));

    server.stop().await;
}
