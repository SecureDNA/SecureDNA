// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use certificates::KeyserverTokenGroup;
use doprf::party::KeyserverId;
use http_client::HttpError;
use scep::error::ScepError;
use scep_client_helpers::ClientCerts;
use scep_integration_tests::make_certs::{make_certs, CreatedCerts, MakeCertsOptions};
use scep_integration_tests::server::{Opts, TestServer};
use shared_types::{hash::HashSpec, requests::RequestId};

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn wrong_client_cert() {
    // make certs, but replace the client certificates with ones signed by a different
    // root
    let certs = {
        let mut certs = make_certs(Default::default());
        let CreatedCerts {
            synth_keypair,
            synth_tokenbundle,
            ..
        } = make_certs(Default::default());
        certs.synth_keypair = synth_keypair;
        certs.synth_tokenbundle = synth_tokenbundle;
        certs
    };

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
        "wrong_cert_test_client".to_owned(),
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
            MakeCertsOptions::default().keyserver_id,
        )
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
    assert!(error
        .to_string()
        .contains("provided certificate from client is invalid"));

    server.stop().await;
}

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn wrong_server_cert() {
    // make certs, but replace the server certificates with ones signed by a different
    // root
    let certs = {
        let mut certs = make_certs(Default::default());
        let CreatedCerts {
            keyserver_keypair,
            keyserver_tokenbundle,
            ..
        } = make_certs(Default::default());
        certs.keyserver_keypair = keyserver_keypair;
        certs.keyserver_tokenbundle = keyserver_tokenbundle;
        certs
    };
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
        "wrong_cert_test_server".to_owned(),
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
            MakeCertsOptions::default().keyserver_id,
        )
        .await
        .unwrap_err();

    if !matches!(
        err,
        scep_client_helpers::Error::Scep {
            source: ScepError::Inner(scep::error::ClientPrevalidation::InvalidCert),
            ..
        }
    ) {
        panic!("Expected ClientPrevalidation::InvalidCert, got {err:?}");
    }

    server.stop().await;
}
