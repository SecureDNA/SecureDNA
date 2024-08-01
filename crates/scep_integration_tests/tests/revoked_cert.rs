// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use tracing::info;

use certificates::revocation::RevocationList;
use certificates::KeyserverTokenGroup;
use doprf::party::KeyserverId;
use http_client::HttpError;
use scep_client_helpers::ClientCerts;
use scep_integration_tests::make_certs::{make_certs, MakeCertsOptions};
use scep_integration_tests::server::{Opts, TestServer};
use shared_types::hash::HashSpec;
use shared_types::requests::RequestId;

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn revoked_client_cert() {
    let certs = make_certs(Default::default());
    let issuer_pks = vec![
        certs.infra_root_keypair.public_key(),
        certs.manu_root_keypair.public_key(),
    ];
    let revocation_list =
        RevocationList::default().with_public_key(certs.synth_keypair.public_key());

    let server = TestServer::spawn(
        Opts {
            issuer_pks: issuer_pks.clone(),
            revocation_list,
            server_cert_chain: certs.keyserver_tokenbundle,
            server_keypair: certs.keyserver_keypair,
            keyserve_fn: Arc::new(|_| unreachable!()),
            hash_spec: HashSpec::dna_normal_cech(),
        },
        async {},
    )
    .await;
    let server_port = server.port();

    let request_id = RequestId::new_unique();
    let http_client = http_client::BaseApiClient::new(request_id);
    let keyserver_client = scep_client_helpers::ScepClient::<KeyserverTokenGroup>::new(
        http_client,
        format!("http://localhost:{server_port}"),
        Arc::new(ClientCerts::with_custom_roots(
            issuer_pks,
            certs.synth_tokenbundle,
            certs.synth_keypair,
        )),
        "wrong_cert_test_client".to_owned(),
    );

    let opened_state = keyserver_client
        .open(
            1,
            None,
            vec![
                KeyserverId::try_from(1).unwrap(),
                KeyserverId::try_from(2).unwrap(),
                KeyserverId::try_from(3).unwrap(),
            ]
            .into(),
            MakeCertsOptions::default().keyserver_id,
            false,
        )
        .await
        .unwrap();

    info!("keyserver opened_state = {opened_state:#?}");

    let hash_total_count = 123;
    let err = keyserver_client
        .authenticate(opened_state, hash_total_count)
        .await
        .unwrap_err();

    let scep_client_helpers::Error::Http(HttpError::RequestError {
        retriable,
        source: error,
        ..
    }) = err
    else {
        panic!("Expected RequestError, got {err:?}");
    };

    assert!(!retriable);
    assert_eq!(
        error.to_string(),
        "the following items in the synthesizer token file are invalid: \
        the synthesizer token registered to 'example.com' is not valid due to revocation"
    );

    server.stop().await;
}
