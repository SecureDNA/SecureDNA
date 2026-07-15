// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use certificates::{DatabaseTokenGroup, KeyserverTokenGroup};
use doprf::{
    party::KeyserverId,
    prf::{CompressedQuery, Query},
};
use doprf_client::packed_ristretto::PackedRistrettos;
use scep::{
    error::{ClientPrevalidation, ScepError},
    states::OpenedClientState,
    types::VerifiableScreeningRequested,
};
use scep_client_helpers::{
    ClientCerts, ScepClientOpenCommon,
    scep_client::{self, HdbOpenParams},
};
use scep_integration_tests::{
    make_certs::{MakeCertsOptions, make_certs},
    mock_screening::{mock_hazard_query, rehash_query},
    server::{Opts, TestServer},
};
use shared_types::{hash::HashSpec, requests::RequestId, synthesis_permission::RawRegion};
use tracing::info;

async fn open_hdb(
    verifiable: VerifiableScreeningRequested,
    fasta_sha3_256_hex: String,
) -> Result<OpenedClientState, scep_client::Error<scep::error::ClientPrevalidation>> {
    let certs = make_certs(Default::default());
    let issuer_pks = vec![
        certs.infra_root_keypair.public_key(),
        certs.manu_root_keypair.public_key(),
    ];

    let keyserver = TestServer::spawn(
        Opts {
            issuer_pks: issuer_pks.clone(),
            revocation_list: Default::default(),
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
            revocation_list: Default::default(),
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

    let input_hashes = vec![mock_hazard_query().into()];
    let hash_total_count = input_hashes.len() as u64;

    let client_certs = Arc::new(ClientCerts::with_custom_roots(
        issuer_pks.clone(),
        certs.synth_tokenbundle.clone(),
        certs.synth_keypair.clone(),
    ));
    let request_id = RequestId::new_unique();
    let http_client = http_client::BaseApiClient::new(request_id).unwrap();
    let keyserver_client = scep_client_helpers::ScepClient::<KeyserverTokenGroup>::new(
        http_client.clone(),
        format!("http://localhost:{keyserver_port}"),
        client_certs.clone(),
        "smoketest".to_owned(),
    );

    let opened_state = keyserver_client
        .open(
            ScepClientOpenCommon {
                nucleotide_total_count: 1,
                last_server_version: None,
                keyserver_id_set: vec![
                    KeyserverId::try_from(1).unwrap(),
                    KeyserverId::try_from(2).unwrap(),
                    KeyserverId::try_from(3).unwrap(),
                ]
                .into(),
                debug_info: false,
            },
            MakeCertsOptions::default().keyserver_id,
        )
        .await
        .unwrap();

    info!("keyserver opened_state = {opened_state:#?}");

    let session_id = keyserver_client
        .authenticate(opened_state, hash_total_count)
        .await
        .unwrap();

    let response = keyserver_client
        .keyserve(
            session_id,
            &PackedRistrettos::<CompressedQuery>::new(input_hashes.clone()),
        )
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

    hdb_client
        .open(
            ScepClientOpenCommon {
                nucleotide_total_count: 1,
                last_server_version: None,
                keyserver_id_set: vec![
                    KeyserverId::try_from(1).unwrap(),
                    KeyserverId::try_from(2).unwrap(),
                    KeyserverId::try_from(3).unwrap(),
                ]
                .into(),
                debug_info: false,
            },
            HdbOpenParams {
                region: RawRegion::ALL,
                with_exemption: false,
                verifiable,
                fasta_sha3_256_hex,
                synthclient_version: "test".to_owned(),
            },
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
pub async fn test_verifiable_screening_needs_fasta_hash() {
    // The hash field is peacefully ignored if verifiable screening was not requested:
    let no_vs_hash = open_hdb(VerifiableScreeningRequested::NotRequested, "f".repeat(64)).await;
    assert!(no_vs_hash.is_ok());
    let no_vs_no_hash = open_hdb(VerifiableScreeningRequested::NotRequested, "".to_owned()).await;
    assert!(no_vs_no_hash.is_ok());

    // If verifiable screening was requested, the hash must be present.
    let vs_hash = open_hdb(VerifiableScreeningRequested::Requested, "f".repeat(64)).await;
    assert!(vs_hash.is_ok());

    // Uppercase hexadecimal strings are accepted too.
    let vs_upper_hash = open_hdb(VerifiableScreeningRequested::Requested, "F".repeat(64)).await;
    assert!(vs_upper_hash.is_ok());

    // If the hash is empty, but verifiable screening was requested, we expect to see an error.
    let vs_no_hash = open_hdb(VerifiableScreeningRequested::Requested, "".to_owned()).await;
    assert!(matches!(
        vs_no_hash,
        Err(scep_client::Error::Scep {
            source: ScepError::Inner(ClientPrevalidation::InvalidFastaHash),
            domain: _
        })
    ));

    // If the hash is malformed, we expect an error, as well.
    let vs_bad_hash = open_hdb(VerifiableScreeningRequested::Requested, "g".repeat(64)).await;
    assert!(matches!(
        vs_bad_hash,
        Err(scep_client::Error::Scep {
            source: ScepError::Inner(ClientPrevalidation::InvalidFastaHash),
            domain: _
        })
    ));
}
