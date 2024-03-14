// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use certificates::{DatabaseTokenGroup, KeyserverTokenGroup};
use doprf::{
    party::KeyserverId,
    prf::{HashPart, Query},
    tagged::{HashTag, TaggedHash},
};
use doprf_client::packed_ristretto::PackedRistrettos;
use scep_client_helpers::ClientCerts;
use scep_integration_tests::{
    make_certs::{make_certs, MakeCertsOptions},
    server::{Opts, TestServer},
};
use shared_types::{hash::HashSpec, requests::RequestId, synthesis_permission::Region};
use tracing::info;

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn smoketest() {
    let certs = make_certs(Default::default());
    let issuer_pks = vec![
        certs.infra_root_keypair.public_key(),
        certs.manu_root_keypair.public_key(),
    ];

    let keyserver = TestServer::spawn(
        Opts {
            issuer_pks: issuer_pks.clone(),
            server_cert_chain: certs.keyserver_tokenbundle,
            server_keypair: certs.keyserver_keypair,
            keyserve_fn: Arc::new(rehash_query),
            hash_spec: HashSpec::dna_normal_cech(),
        },
        async {},
    )
    .await;

    let hdb = TestServer::spawn(
        Opts {
            issuer_pks: issuer_pks.clone(),
            server_cert_chain: certs.database_tokenbundle,
            server_keypair: certs.database_keypair,
            keyserve_fn: Arc::new(rehash_query),
            hash_spec: HashSpec::dna_normal_cech(),
        },
        async {},
    )
    .await;

    let keyserver_port = keyserver.port();
    let hdb_port = hdb.port();

    let input_hashes = vec![
        Query::hash_from_bytes_for_tests_only(&[0]).into(),
        Query::hash_from_bytes_for_tests_only(&[1]).into(),
        Query::hash_from_bytes_for_tests_only(&[2]).into(),
        Query::hash_from_bytes_for_tests_only(&[3]).into(),
        Query::hash_from_bytes_for_tests_only(&[4]).into(),
    ];
    let hash_total_count = input_hashes.len() as u64;

    let client_certs = Arc::new(ClientCerts::with_custom_roots(
        issuer_pks.clone(),
        certs.synth_tokenbundle.clone(),
        certs.synth_keypair.clone(),
    ));
    let request_id = RequestId::new_unique();
    let http_client = http_client::BaseApiClient::new(request_id);
    let keyserver_client = scep_client_helpers::ScepClient::<KeyserverTokenGroup>::new(
        http_client.clone(),
        format!("http://localhost:{keyserver_port}"),
        client_certs.clone(),
        "smoketest".to_owned(),
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
        )
        .await
        .unwrap();

    info!("keyserver opened_state = {opened_state:#?}");

    keyserver_client
        .authenticate(opened_state, hash_total_count)
        .await
        .unwrap();

    let response = keyserver_client
        .keyserve(&PackedRistrettos::<Query>::new(input_hashes.clone()))
        .await
        .unwrap();

    assert_eq!(
        response.encoded_items(),
        input_hashes
            .into_iter()
            .map(|q_bytes| {
                let q: Query = q_bytes.try_into().unwrap();
                rehash_query(q).into()
            })
            .collect::<Vec<[u8; 32]>>()
    );

    let hdb_client = scep_client_helpers::ScepClient::<DatabaseTokenGroup>::new(
        http_client,
        format!("http://localhost:{hdb_port}"),
        client_certs,
        "smoketest".to_owned(),
    );

    let opened_state = hdb_client
        .open(
            1,
            None,
            vec![
                KeyserverId::try_from(1).unwrap(),
                KeyserverId::try_from(2).unwrap(),
                KeyserverId::try_from(3).unwrap(),
            ]
            .into(),
            Region::All,
        )
        .await
        .unwrap();

    info!("hdb opened_state = {opened_state:#?}");

    hdb_client
        .authenticate(opened_state, hash_total_count)
        .await
        .unwrap();

    let tagged_hashes =
        PackedRistrettos::from_iter(response.iter_encoded().enumerate().map(|(i, hash)| {
            TaggedHash {
                tag: HashTag::new(i == 0, 0, i),
                hash: (*hash).try_into().unwrap(),
            }
        }));

    let screen_response = hdb_client.screen(&tagged_hashes).await.unwrap();

    info!("hdb screen_response = {screen_response:#?}");

    info!("finished test");

    keyserver.stop().await;
    hdb.stop().await;
}

/// A dummy processing function so we don't need a real keyshare
fn rehash_query(query: Query) -> HashPart {
    let bytes: [u8; 32] = query.into();
    HashPart::hash_from_bytes_for_tests_only(&bytes)
}
