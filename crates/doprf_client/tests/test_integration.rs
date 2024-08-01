// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(feature = "centralized_keygen")]

use std::fs::File;
use std::io::Write;
use std::net::TcpListener;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::{cell::RefCell, collections::HashMap};

use futures::{future, pin_mut};

use doprf::party::KeyserverId;
use doprf::prf::KeyShare;
use doprf::shims::{genkey, genkeyshares};
use doprf::{active_security::Commitment, shims::genactivesecuritykey};
use doprf_client::server_selection::{
    ServerEnumerationSource, ServerSelectionConfig, ServerSelector,
};
use doprf_client::{server_version_handler::LastServerVersionHandler, DoprfConfig};
use hdb::shims::genhdb;
use http_client::{BaseApiClient, HttpsToHttpRewriter};
use minhttp::mpserver::common::{default_listen_fn, read_no_disk, stub_cfg};
use minhttp::mpserver::{traits::ValidServerSetup, ExternalWorld, PlaneConfig, ServerConfig};
use pipeline_bridge::OrganismType;
use quickdna::{DnaSequence, Nucleotide};
use scep_client_helpers::ClientCerts;
use shared_types::hdb::{ConsolidatedHazardResult, HitRegion};
use shared_types::{
    requests::{RequestContext, RequestId},
    synthesis_permission::{Region, SynthesisPermission},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_hdb() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // 1. Generate a key
    let key: KeyShare = {
        let mut stdout: Vec<u8> = vec![];
        genkey::main(&genkey::Opts {}, &mut stdout, &mut vec![]).expect("Generating key failed");
        std::str::from_utf8(&stdout)
            .expect("Got invalid utf8 key")
            .trim_end()
            .parse()
            .expect("Got invalid keyshare")
    };

    // 2. Create a temporary database directory
    let tmp_dir = tempfile::Builder::new()
        .prefix("db_dir")
        .tempdir()
        .expect("Creating temp dir failed");
    // TODO test with existing db path
    let db_path = tmp_dir.path().join("hdb");
    let artifacts_path = tmp_dir.path().join("artifacts");
    std::fs::create_dir(&artifacts_path).expect("Creating artifacts dir failed");
    let aggregated_path = artifacts_path.join("aggregated.json");
    let dna_normal_fraglist_path = artifacts_path.join("dna42.fraglist");
    let dna_runt_fraglist_path = artifacts_path.join("dna30.fraglist");
    let protein_fraglist_path = artifacts_path.join("protein.fraglist");

    // 3. Choose some hazard strings and write them to artifacts, split between the files
    let hazard = pipeline_bridge::AggregatedHazard {
        hazard_meta: pipeline_bridge::HazardProperties {
            path_name: "Testus_Integrationitis".into(),
            common_name: "T. Integrationitis".into(),
            accessions: vec!["TST_00000".into()],
            tags: vec![
                pipeline_bridge::Tag::SelectAgentAphis,
                pipeline_bridge::Tag::PRCExportControlPart1,
            ],
            tiled: false,
            organism_type: OrganismType::Virus,
        },
        dna_variant_42mers_path: dna_normal_fraglist_path.clone(),
        dna_variant_30mers_path: dna_runt_fraglist_path.clone(),
        protein_variants_path: protein_fraglist_path.clone(),
    };
    serde_json::to_writer(
        std::fs::File::create(aggregated_path).unwrap(),
        &vec![hazard],
    )
    .unwrap();
    let dna_normal_fraglist = RefCell::new(File::create(&dna_normal_fraglist_path).unwrap());
    let dna_runt_fraglist = RefCell::new(File::create(&dna_runt_fraglist_path).unwrap());
    let protein_fraglist = RefCell::new(File::create(&protein_fraglist_path).unwrap());
    // TODO test with different sets of strings, including empty strings, duplicated strings,
    // and more than 128 strings.

    const HAZ_AA: &str = "LMWLVDQVLLSRATLSGTCQ"; // 20
    const HAZ_AA_DNA: &str = "TTAATGTGGTTAGTGGATCAGGTGCTGCTGAGCAGAGCTACGCTCTCCGGCACATGTCAG"; // 60

    const HAZ_NORMAL: &str = "CGGCTTTTTGGTAGTTAGGCTATTGGTAGGATAGATGTTCGCA"; // 43
    const HAZ_NORMAL_1: &str = "CGGCTTTTTGGTAGTTAGGCTATTGGTAGGATAGATGTTCGC"; // 42, first window of HAZ_NORMAL
    const HAZ_NORMAL_2: &str = "GGCTTTTTGGTAGTTAGGCTATTGGTAGGATAGATGTTCGCA"; // 42, second window of HAZ_NORMAL

    const HAZ_RUNT: &str = "GTACAGACCACAGTTGCCGCGCCCTCAATC"; // 30

    fn to_canonical_string(dna_seq: &str) -> String {
        let dna_seq = DnaSequence::<Nucleotide>::from_str(dna_seq).unwrap();
        dna_seq.canonical().to_string()
    }

    let hazards = [
        (
            Some(pipeline_bridge::Provenance::WildType),
            &protein_fraglist,
            HAZ_AA.to_string(),
        ),
        (
            None,
            &dna_normal_fraglist,
            to_canonical_string(HAZ_NORMAL_1),
        ),
        (
            None,
            &dna_normal_fraglist,
            to_canonical_string(HAZ_NORMAL_2),
        ),
        (None, &dna_runt_fraglist, to_canonical_string(HAZ_RUNT)),
    ];
    for (provenance, fraglist, seq) in hazards.iter() {
        let entry = pipeline_bridge::VariantEntry {
            variant: seq.into(),
            provenance: *provenance,
            log_likelihood: None,
            reverse_screened: None,
            is_common: false,
        };

        let json = serde_json::to_string(&entry).expect("failed to serialize variant");
        writeln!(fraglist.borrow_mut(), "{}", json.trim()).unwrap();
    }
    // purposely write trailing newlines to only one file to test both behaviors
    writeln!(dna_normal_fraglist.borrow_mut()).unwrap();

    // 4. Put the strings in the temporary database directory
    let gen_hdb_opts = genhdb::Opts {
        secret_key: key,
        artifacts_dir: artifacts_path,
        database: db_path.clone(),
        command: genhdb::Command::New { force: false },
        skip_build_info: true,
        num_threads: 1, // TODO test with multiple threads?
        sort_only: false,
        index_mb: 1,
    };

    genhdb::main(&gen_hdb_opts).unwrap();

    // 5. Generate keyshares
    const KEYHOLDERS_REQUIRED: NonZeroU32 = match NonZeroU32::new(3) {
        Some(x) => x,
        None => unreachable!(),
    };
    const NUM_KEYHOLDERS: NonZeroU32 = match NonZeroU32::new(5) {
        Some(x) => x,
        None => unreachable!(),
    };
    let keyshare_opts = genkeyshares::Opts {
        secret_key: key,
        keyholders_required: KEYHOLDERS_REQUIRED,
        num_keyholders: NUM_KEYHOLDERS,
    };

    let mut stdout: Vec<u8> = vec![];
    genkeyshares::main(&keyshare_opts, &mut stdout, &mut vec![])
        .expect("Generating keyshares failed");
    let shares = std::str::from_utf8(&stdout)
        .expect("Invalid utf8 keyshares")
        .lines()
        .map(|l| KeyShare::from_str(l).expect("Got invalid keyshare"))
        .collect::<Vec<_>>();

    let gen_as_key_opts = genactivesecuritykey::Opts {
        secret_key: key,
        keyholders_required: KEYHOLDERS_REQUIRED,
        keyshares: shares.clone(),
    };

    let mut stdout: Vec<u8> = vec![];
    genactivesecuritykey::main(&gen_as_key_opts, &mut stdout, &mut vec![])
        .expect("Generating active security key failed");
    let active_security_key = std::str::from_utf8(&stdout)
        .expect("Invalid utf8 commitments")
        .lines()
        .map(|l| {
            Commitment::from_str(l)
                .expect("Got invalid commitment when generating active security key")
        })
        .collect::<Vec<_>>();

    // 6. Start the servers

    fn find_unused_port() -> TcpListener {
        // The ":0" here asks the OS to pick an unused port.
        TcpListener::bind("127.0.0.1:0").unwrap()
    }

    let certs_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/certs");

    let hdb_listener = find_unused_port();
    let address = hdb_listener.local_addr().unwrap();
    let hdb_port = address.port();

    let mut servers = vec![];
    let mut listeners = vec![hdb_listener];
    let mut ks_ports = vec![];

    let app_cfg = hdbserver::Config {
        database: db_path,
        max_heavy_clients: 1,
        disk_parallelism_per_server: 1,
        disk_parallelism_per_request: 1,
        hash_spec_path: None,
        yubico_api_client_id: None,
        yubico_api_secret_key: None,
        scep_json_size_limit: 100_000,
        et_size_limit: 1_000_000,
        exemption_roots: format!("{certs_dir}/exemption-roots").into(),
        manufacturer_roots: format!("{certs_dir}/manufacturer-roots").into(),
        revocation_list: None,
        token_file: format!("{certs_dir}/database-token.dt").into(),
        keypair_file: format!("{certs_dir}/database-token.priv").into(),
        keypair_passphrase_file: format!("{certs_dir}/database-token.passphrase").into(),
        allow_insecure_cookie: true,
        event_store_path: ":memory:".into(),
    };
    let server_config = Arc::new(ServerConfig {
        main: PlaneConfig {
            address: Some(address),
            tls_config: None,
            max_connections: PlaneConfig::DEFAULT_MAX_CONNECTIONS,
            custom: app_cfg,
        },
        monitoring: PlaneConfig::default(),
        control: PlaneConfig::default(),
    });
    let external_world = ExternalWorld {
        listen: default_listen_fn,
        load_cfg: stub_cfg(move || (*server_config).clone()),
        read_file: read_no_disk,
    };
    let server = hdbserver::server_setup()
        .to_server_setup()
        .build_with_external_world(external_world);
    servers.push(server);

    for k in 0..NUM_KEYHOLDERS.get() {
        let listener = find_unused_port();
        let address = listener.local_addr().unwrap();
        let keyserver_file_base =
            PathBuf::from(format!("{certs_dir}/keyserver-token-{:02}", k + 1));
        let app_cfg = keyserver::Config {
            id: KeyserverId::try_from(k + 1).unwrap(),
            keyholders_required: KEYHOLDERS_REQUIRED.get(),
            keyshare: shares[k as usize],
            max_heavy_clients: 1,
            crypto_parallelism_per_server: None,
            crypto_parallelism_per_request: None,
            active_security_key: active_security_key.clone(),
            scep_json_size_limit: 100_000,
            manufacturer_roots: format!("{certs_dir}/manufacturer-roots").into(),
            revocation_list: None,
            token_file: keyserver_file_base.with_extension("kt"),
            keypair_file: keyserver_file_base.with_extension("priv"),
            keypair_passphrase_file: keyserver_file_base.with_extension("passphrase"),
            allow_insecure_cookie: true,
            event_store_path: ":memory:".into(),
        };
        let server_config = Arc::new(ServerConfig {
            main: PlaneConfig {
                address: Some(address),
                tls_config: None,
                max_connections: PlaneConfig::DEFAULT_MAX_CONNECTIONS,
                custom: app_cfg,
            },
            monitoring: PlaneConfig::default(),
            control: PlaneConfig::default(),
        });
        let external_world = ExternalWorld {
            listen: default_listen_fn,
            load_cfg: stub_cfg(move || (*server_config).clone()),
            read_file: read_no_disk,
        };
        let server = keyserver::server_setup()
            .to_server_setup()
            .build_with_external_world(external_world);
        servers.push(server);
        // maintain the TcpListener instances until all ports have been allocated
        listeners.push(listener);
        ks_ports.push(address.port());
    }

    // Now drop listeners so that the servers are able to listen on the assigned ports
    drop(listeners);
    // Load all server configs; once this completes, all servers are listening on their assigned ports
    future::try_join_all(servers.iter().map(|s| s.reload_cfg()))
        .await
        .expect("server was unable to load cfg");

    let servers = future::join_all(servers.iter().map(|s| s.serve()));

    let tests = async {
        // 7. Use client to query for given strings

        // localhost.securedna.org and its subdomains simply resolve to 127.0.0.1,
        // but having different subdomains lets us isolate cookies among them.
        // (Cookies aren't isolated by port alone.)
        const BASE_DOMAIN: &str = "localhost.securedna.org";

        let request_id = RequestId::from_str("test_request").unwrap();
        let request_ctx = RequestContext::single(request_id);
        let api_client = HttpsToHttpRewriter::inject(BaseApiClient::new(request_ctx.id.clone()));

        // Run server selection (without enumeration since we don't want to run a local DNS server lol)
        let server_selector = Arc::new(
            ServerSelector::new(
                ServerSelectionConfig {
                    enumeration_source: ServerEnumerationSource::Fixed {
                        keyserver_domains: (0..KEYHOLDERS_REQUIRED.get())
                            .map(|i| {
                                let num = i + 1;
                                let port = ks_ports[i as usize];
                                format!("ks{num}.{BASE_DOMAIN}:{port}")
                            })
                            .collect(),
                        hdb_domains: vec![format!("db1.{BASE_DOMAIN}:{hdb_port}")],
                    },
                    soft_timeout: None,
                    blocking_timeout: None,
                    soft_extra_keyserver_threshold: None,
                    soft_extra_hdb_threshold: None,
                },
                api_client.clone(),
            )
            .await
            .unwrap(),
        );

        let client_certs = Arc::new(ClientCerts::load_test_certs());
        let server_versions = Arc::new(tokio::sync::Mutex::new(HashMap::<String, u64>::new()));

        let run_query = |records: Vec<String>, region: Region| {
            let server_selector = &server_selector;
            let request_ctx = &request_ctx;
            let api_client = api_client.clone();
            let sequences = records
                .iter()
                .map(|r| DnaSequence::<Nucleotide>::from_str(r).unwrap())
                .collect::<Vec<_>>();
            let server_versions = server_versions.clone();

            let certs = client_certs.clone();
            async move {
                let output = doprf_client::process(DoprfConfig {
                    api_client: &api_client,
                    server_selector: server_selector.clone(),
                    request_ctx,
                    certs,
                    region,
                    debug_info: false,
                    sequences: &sequences[..],
                    max_windows: u64::MAX,
                    version_hint: "integration_test".to_owned(),
                    ets: vec![],
                    server_version_handler: &LastServerVersionHandler::new(
                        {
                            let server_versions = server_versions.clone();
                            Box::new(move |domain| {
                                let server_versions = server_versions.clone();
                                Box::pin(async move {
                                    Ok(server_versions.lock().await.get(&domain).copied())
                                })
                            })
                        },
                        {
                            let server_versions = server_versions.clone();
                            Box::new(move |domain, server_version| {
                                let server_versions = server_versions.clone();
                                Box::pin(async move {
                                    server_versions.lock().await.insert(domain, server_version);
                                    Ok(())
                                })
                            })
                        },
                    ),
                })
                .await
                .unwrap();

                println!("{:#?}", output.response);

                output
                    .response
                    .results
                    .into_iter()
                    .flat_map(|matched| {
                        let ConsolidatedHazardResult { hit_regions, .. } = matched.clone();
                        hit_regions
                            .into_iter()
                            .map(|hit_region| (hit_region.seq_range_start, matched.clone()))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<(usize, ConsolidatedHazardResult)>>()
            }
        };

        let t_integrationitis = shared_types::hdb::Organism {
            name: "T. Integrationitis".into(),
            organism_type: OrganismType::Virus,
            ans: vec!["TST_00000".into()],
            tags: vec![
                pipeline_bridge::Tag::PRCExportControlPart1,
                pipeline_bridge::Tag::SelectAgentAphis,
            ],
        };

        // based on the tags, `Us`, `Prc`, and no-region requests should be denied...
        for region in [Region::Us, Region::Prc, Region::All] {
            assert_eq!(
                run_query(
                    vec![
                        HAZ_RUNT.to_owned(),
                        "GACCCCCAATCACCGCCTCATACTTCTTTG".to_owned(),
                    ],
                    region,
                )
                .await,
                vec![(
                    0,
                    ConsolidatedHazardResult {
                        record: 0,
                        hit_regions: vec![HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 30
                        }],
                        synthesis_permission: SynthesisPermission::Denied,
                        most_likely_organism: t_integrationitis.clone(),
                        organisms: vec![t_integrationitis.clone()],
                        is_dna: true,
                        is_wild_type: None,
                        exempt: false,
                    }
                )]
            );
        }

        // ...but `Eu` requests should be allowed
        assert_eq!(
            run_query(
                vec![
                    HAZ_RUNT.to_owned(),
                    "GACCCCCAATCACCGCCTCATACTTCTTTG".to_owned(),
                ],
                Region::Eu
            )
            .await,
            vec![(
                0,
                ConsolidatedHazardResult {
                    record: 0,
                    hit_regions: vec![HitRegion {
                        seq_range_start: 0,
                        seq_range_end: 30
                    }],
                    synthesis_permission: SynthesisPermission::Granted,
                    most_likely_organism: t_integrationitis.clone(),
                    organisms: vec![t_integrationitis.clone()],
                    is_dna: true,
                    is_wild_type: None,
                    exempt: false,
                }
            )]
        );

        assert_eq!(
            run_query(
                vec![
                    HAZ_AA_DNA.to_owned(),
                    HAZ_NORMAL.to_owned(),
                    HAZ_RUNT.to_owned(),
                ],
                Region::All
            )
            .await,
            vec![
                (
                    0,
                    ConsolidatedHazardResult {
                        record: 0,
                        hit_regions: vec![HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 60
                        }],
                        synthesis_permission: SynthesisPermission::Denied,
                        most_likely_organism: t_integrationitis.clone(),
                        organisms: vec![t_integrationitis.clone()],
                        is_dna: false,
                        is_wild_type: Some(true),
                        exempt: false,
                    }
                ),
                (
                    0,
                    ConsolidatedHazardResult {
                        record: 1,
                        hit_regions: vec![HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 43, // two windows
                        }],
                        synthesis_permission: SynthesisPermission::Denied,
                        most_likely_organism: t_integrationitis.clone(),
                        organisms: vec![t_integrationitis.clone()],
                        is_dna: true,
                        is_wild_type: None,
                        exempt: false,
                    }
                ),
                (
                    0,
                    ConsolidatedHazardResult {
                        record: 2,
                        hit_regions: vec![HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 30
                        }],
                        synthesis_permission: SynthesisPermission::Denied,
                        most_likely_organism: t_integrationitis.clone(),
                        organisms: vec![t_integrationitis.clone()],
                        is_dna: true,
                        is_wild_type: None,
                        exempt: false,
                    }
                ),
            ]
        );

        // Make sure we return correct records even when sequences are too short to generate windows
        assert_eq!(
            run_query(
                vec![
                    "CATTAG".to_owned(),
                    HAZ_NORMAL.to_owned(),
                    "CATTAG".to_owned(),
                    "CATTAG".to_owned(),
                    "CATTAG".to_owned(),
                    HAZ_RUNT.to_owned(),
                    HAZ_RUNT.to_owned(),
                    "CATTAG".to_owned(),
                    HAZ_AA_DNA.to_owned(),
                    "CATTAG".to_owned(),
                ],
                Region::All
            )
            .await,
            vec![
                (
                    0,
                    ConsolidatedHazardResult {
                        record: 1,
                        hit_regions: vec![HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 43, // two windows
                        }],
                        synthesis_permission: SynthesisPermission::Denied,
                        most_likely_organism: t_integrationitis.clone(),
                        organisms: vec![t_integrationitis.clone()],
                        is_dna: true,
                        is_wild_type: None,
                        exempt: false,
                    }
                ),
                (
                    0,
                    ConsolidatedHazardResult {
                        record: 5,
                        hit_regions: vec![HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 30
                        }],
                        synthesis_permission: SynthesisPermission::Denied,
                        most_likely_organism: t_integrationitis.clone(),
                        organisms: vec![t_integrationitis.clone()],
                        is_dna: true,
                        is_wild_type: None,
                        exempt: false,
                    }
                ),
                (
                    0,
                    ConsolidatedHazardResult {
                        record: 6,
                        hit_regions: vec![HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 30
                        }],
                        synthesis_permission: SynthesisPermission::Denied,
                        most_likely_organism: t_integrationitis.clone(),
                        organisms: vec![t_integrationitis.clone()],
                        is_dna: true,
                        is_wild_type: None,
                        exempt: false,
                    }
                ),
                (
                    0,
                    ConsolidatedHazardResult {
                        record: 8,
                        hit_regions: vec![HitRegion {
                            seq_range_start: 0,
                            seq_range_end: 60
                        }],
                        synthesis_permission: SynthesisPermission::Denied,
                        most_likely_organism: t_integrationitis.clone(),
                        organisms: vec![t_integrationitis.clone()],
                        is_dna: false,
                        is_wild_type: Some(true),
                        exempt: false,
                    }
                ),
            ]
        );
    };
    pin_mut!(tests);

    let result = future::select(tests, servers).await;

    // there is something wrong if the servers future finishes first
    if let future::Either::Right(_) = result {
        panic!("servers stopped running before the tests ended");
    }
}
