// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use certificates::KeyserverTokenGroup;
use doprf::party::KeyserverId;
use scep::error::{ClientPrevalidation, ScepError};
use scep_client_helpers::ClientCerts;
use scep_integration_tests::make_certs::{make_certs, MakeCertsOptions};
use scep_integration_tests::server::{Opts, TestServer};
use shared_types::{hash::HashSpec, requests::RequestId};

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn wrong_keyserver_id() {
    let server_actual_id = KeyserverId::try_from(2).unwrap();
    let client_expected_id = KeyserverId::try_from(1).unwrap();

    let certs = make_certs(MakeCertsOptions {
        keyserver_id: server_actual_id,
    });

    let issuer_pks = vec![
        certs.infra_root_keypair.public_key(),
        certs.manu_root_keypair.public_key(),
    ];
    let server = TestServer::spawn(
        Opts {
            issuer_pks: issuer_pks.clone(),
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
        "wrong_keyserver_id_test".to_owned(),
    );

    let err = keyserver_client
        .open(
            1,
            None,
            vec![
                KeyserverId::try_from(1).unwrap(),
                KeyserverId::try_from(2).unwrap(),
                KeyserverId::try_from(3).unwrap(),
            ]
            .into(),
            client_expected_id,
        )
        .await
        .unwrap_err();

    let expected_err = scep_client_helpers::Error::Scep {
        source: ScepError::Inner(ClientPrevalidation::InvalidKeyserverId {
            expected: client_expected_id,
            in_cert: server_actual_id,
        }),
        domain: keyserver_client.domain().to_owned(),
    };

    assert_eq!(err.to_string(), expected_err.to_string(),);

    server.stop().await;
}
