// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use certificates::{DatabaseTokenGroup, ExemptionListTokenGroup, KeyserverTokenGroup, TokenBundle};
use doprf::{
    party::KeyserverId,
    prf::Query,
    tagged::{HashTag, TaggedHash},
};
use doprf_client::packed_ristretto::PackedRistrettos;
use scep_client_helpers::ClientCerts;
use scep_integration_tests::{
    make_certs::{make_certs, MakeCertsOptions},
    mock_screening::{
        mock_hazard_cert_an_organism, mock_hazard_cert_hash_organism, mock_hazard_hash,
        mock_hazard_organism, mock_hazard_query, rehash_query,
    },
    server::{Opts, TestServer},
};
use shared_types::{
    hash::HashSpec,
    hdb::{ConsolidatedHazardResult, HdbScreeningResult},
    requests::RequestId,
    synthesis_permission::{Region, SynthesisPermission},
};
use tracing::info;

struct Scenario {
    screen_hashes: Vec<[u8; 32]>,
    exemptions: Option<(TokenBundle<ExemptionListTokenGroup>, Vec<[u8; 32]>)>,
    expected_result: HdbScreeningResult,
}

async fn test_scenario(scenario: Scenario) {
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

    let input_hashes = scenario.screen_hashes;
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
            scenario.exemptions.is_some(),
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

    // The exact value doesn't matter, as the integration tests
    // launch hdbserver with --yubico-api-client-id allow_all.
    let otp = "123456".to_owned();
    let screen_response = match scenario.exemptions {
        None => hdb_client.screen(&tagged_hashes).await.unwrap(),
        Some((elt, elt_hashes)) => hdb_client
            .screen_with_elt(&tagged_hashes, &elt, &elt_hashes.into(), otp)
            .await
            .unwrap(),
    };

    info!("hdb screen_response = {screen_response:#?}");

    assert_eq!(screen_response, scenario.expected_result);

    info!("finished test");

    keyserver.stop().await;
    hdb.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn smoketest() {
    test_scenario(Scenario {
        screen_hashes: vec![
            Query::hash_from_bytes_for_tests_only(&[0]).into(),
            Query::hash_from_bytes_for_tests_only(&[1]).into(),
            Query::hash_from_bytes_for_tests_only(&[2]).into(),
            Query::hash_from_bytes_for_tests_only(&[3]).into(),
            Query::hash_from_bytes_for_tests_only(&[4]).into(),
        ],
        exemptions: None,
        expected_result: HdbScreeningResult {
            results: vec![],
            debug_hdb_responses: None,
            provider_reference: None,
        },
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn test_hazard_denied() {
    test_scenario(Scenario {
        screen_hashes: vec![mock_hazard_query().into()],
        exemptions: None,
        expected_result: HdbScreeningResult {
            results: vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![],
                synthesis_permission: SynthesisPermission::Denied,
                most_likely_organism: mock_hazard_organism(),
                organisms: vec![mock_hazard_organism()],
                is_dna: true,
                is_wild_type: None,
                exempt: false,
            }],
            debug_hdb_responses: None,
            provider_reference: None,
        },
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn test_hazard_exempt_organism() {
    let elt = hdb::exemption::make_test_elt(vec![mock_hazard_cert_an_organism()]);
    test_scenario(Scenario {
        screen_hashes: vec![mock_hazard_query().into()],
        exemptions: Some((elt, vec![])),
        expected_result: HdbScreeningResult {
            results: vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![],
                synthesis_permission: SynthesisPermission::Granted,
                most_likely_organism: mock_hazard_organism(),
                organisms: vec![mock_hazard_organism()],
                is_dna: true,
                is_wild_type: None,
                exempt: true,
            }],
            debug_hdb_responses: None,
            provider_reference: None,
        },
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn test_hazard_exempt_hash() {
    let elt = hdb::exemption::make_test_elt(vec![mock_hazard_cert_hash_organism()]);
    let elt_hashes = vec![mock_hazard_hash()].into_iter().collect();
    test_scenario(Scenario {
        screen_hashes: vec![mock_hazard_query().into()],
        exemptions: Some((elt, elt_hashes)),
        expected_result: HdbScreeningResult {
            results: vec![ConsolidatedHazardResult {
                record: 0,
                hit_regions: vec![],
                synthesis_permission: SynthesisPermission::Granted,
                most_likely_organism: mock_hazard_organism(),
                organisms: vec![mock_hazard_organism()],
                is_dna: true,
                is_wild_type: None,
                exempt: true,
            }],
            debug_hdb_responses: None,
            provider_reference: None,
        },
    })
    .await;
}
