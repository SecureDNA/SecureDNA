// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Context;
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use goose::logger::GooseLogFormat::Csv;
use goose::prelude::*;

use performance_tests::analyzer::runner::{extract_goose_metrics, print_metrics_comparison};
use performance_tests::loadtest::config::{
    set_authorized_client, set_authorized_client_with_keyserver_ids,
};
use performance_tests::loadtest::nmon::{process_nmon, start_nmon, stop_nmon};
use performance_tests::loadtest::scenario::{
    hdb_random_bytes_v1, hdb_random_bytes_v2, hdb_random_bytes_v3, hdb_random_bytes_v4,
    hdb_repeat_bytes_v1, hdb_repeat_bytes_v2, hdb_repeat_bytes_v3, hdb_repeat_bytes_v4,
    ks_random_bytes_v1, ks_random_bytes_v2, ks_random_bytes_v3, ks_random_bytes_v4,
    ks_repeat_bytes_v1, ks_repeat_bytes_v2, ks_repeat_bytes_v3, ks_repeat_bytes_v4,
    random_sequence, single_known_organism, single_organism_permutations, unimplemented_scenario,
};
use performance_tests::loadtest::util::create_results_dir;
use performance_tests::shared::config::{load_config, ApiVersion, ComparisonMode};
use performance_tests::shared::server::{
    create_network, destroy_network, show_running, start_hdbservers, start_keyservers,
    start_synthclient, stop_container,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = load_config()?;

    println!("Config Dump: {config:?}");

    let mut ids = vec![];

    let network_id =
        if config.keyservers.is_some() || config.hdbservers.is_some() || config.clients.is_some() {
            Some(create_network(&config).await?)
        } else {
            None
        };

    if let Some(keyserver_cfg) = &config.keyservers {
        ids.extend(
            start_keyservers(
                keyserver_cfg,
                &config.comparison_mode,
                network_id.as_deref().unwrap(),
            )
            .await?,
        );
    }

    if let Some(hdbserver_cfg) = &config.hdbservers {
        ids.extend(
            start_hdbservers(
                hdbserver_cfg,
                &config.comparison_mode,
                network_id.as_deref().unwrap(),
            )
            .await?,
        );
    }

    if let Some(clients_cfg) = &config.clients {
        ids.extend(
            start_synthclient(
                clients_cfg,
                &config.comparison_mode,
                network_id.as_deref().unwrap(),
            )
            .await?,
        );
    }

    if !ids.is_empty() {
        println!("Running containers: {}", show_running().await);
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    create_results_dir(timestamp);

    let mut test_types = HashMap::from([(
        "baseline".to_string(),
        (&config.url1, &config.api_version_url1),
    )]);

    if config.comparison_mode == ComparisonMode::Compare {
        test_types.insert("new".to_string(), (&config.url2, &config.api_version_url2));
    } else {
        println!("Comparison mode DISABLED - only running/displaying baseline build")
    }

    let mut metrics = HashMap::new();

    let mut scenario_name = String::new();
    let mut user_count = 0;

    for (test, (host, api_version)) in test_types.iter() {
        let log_base = Path::new("results")
            .join(timestamp.to_string())
            .join(format!("{test}-{timestamp}"))
            .display()
            .to_string();

        let mut nmon_pid = String::from("-1");

        if config.nmon_enabled {
            nmon_pid = start_nmon(format!("{}.nmon", &log_base).as_str());
            println!("Started NMON with pid: {}", &nmon_pid);
        }

        let goose_instance = GooseAttack::initialize()?
            .register_scenario(match **api_version {
                ApiVersion::Api1 => {
                    scenario!("1.ClientKnownHazard").register_transaction(unimplemented_scenario())
                }
                ApiVersion::Api2 => scenario!("1.ClientKnownHazard")
                    .register_transaction(transaction!(set_authorized_client).set_on_start()),
                ApiVersion::Api3 => scenario!("1.ClientKnownHazard")
                    .register_transaction(transaction!(set_authorized_client).set_on_start()),
                ApiVersion::Api4 => scenario!("1.ClientKnownHazard")
                    .register_transaction(single_known_organism(config.hash_count)),
            })
            .register_scenario(match **api_version {
                ApiVersion::Api1 => scenario!("2.ClientKnownHazardPermutations")
                    .register_transaction(unimplemented_scenario()),
                ApiVersion::Api2 => scenario!("2.ClientKnownHazardPermutations")
                    .register_transaction(transaction!(set_authorized_client).set_on_start()),
                ApiVersion::Api3 => scenario!("2.ClientKnownHazardPermutations")
                    .register_transaction(transaction!(set_authorized_client).set_on_start()),
                ApiVersion::Api4 => scenario!("2.ClientKnownHazardPermutations")
                    .register_transaction(single_organism_permutations(config.hash_count)),
            })
            .register_scenario(match **api_version {
                ApiVersion::Api1 => scenario!("3.ClientRandomSequence")
                    .register_transaction(unimplemented_scenario()),
                ApiVersion::Api2 => scenario!("3.ClientRandomSequence")
                    .register_transaction(transaction!(set_authorized_client).set_on_start()),
                ApiVersion::Api3 => scenario!("3.ClientRandomSequence")
                    .register_transaction(transaction!(set_authorized_client).set_on_start()),
                ApiVersion::Api4 => scenario!("3.ClientRandomSequence")
                    .register_transaction(random_sequence(config.hash_count)),
            })
            .register_scenario(match **api_version {
                ApiVersion::Api1 => scenario!("4.KSRandomBytes")
                    .register_transaction(ks_random_bytes_v1(config.hash_count)),
                ApiVersion::Api2 => scenario!("4.KSRandomBytes")
                    .register_transaction(
                        transaction!(set_authorized_client_with_keyserver_ids).set_on_start(),
                    )
                    .register_transaction(ks_random_bytes_v2(config.hash_count)),
                ApiVersion::Api3 => scenario!("4.KSRandomBytes")
                    .register_transaction(
                        transaction!(set_authorized_client_with_keyserver_ids).set_on_start(),
                    )
                    .register_transaction(ks_random_bytes_v3(config.hash_count)),
                ApiVersion::Api4 => scenario!("4.KSRandomBytes")
                    .register_transaction(
                        transaction!(set_authorized_client_with_keyserver_ids).set_on_start(),
                    )
                    .register_transaction(ks_random_bytes_v4(config.hash_count)),
            })
            .register_scenario(match **api_version {
                ApiVersion::Api1 => scenario!("5.HDBRandomBytes")
                    .register_transaction(hdb_random_bytes_v1(config.hash_count)),
                ApiVersion::Api2 => scenario!("5.HDBRandomBytes")
                    .register_transaction(transaction!(set_authorized_client).set_on_start())
                    .register_transaction(hdb_random_bytes_v2(config.hash_count)),
                ApiVersion::Api3 => scenario!("5.HDBRandomBytes")
                    .register_transaction(transaction!(set_authorized_client).set_on_start())
                    .register_transaction(hdb_random_bytes_v3(config.hash_count)),
                ApiVersion::Api4 => scenario!("5.HDBRandomBytes")
                    .register_transaction(transaction!(set_authorized_client).set_on_start())
                    .register_transaction(hdb_random_bytes_v4(config.hash_count)),
            })
            .register_scenario(match **api_version {
                ApiVersion::Api1 => scenario!("6.HDBRepeatBytes")
                    .register_transaction(hdb_repeat_bytes_v1(config.hash_count)),
                ApiVersion::Api2 => scenario!("6.HDBRepeatBytes")
                    .register_transaction(transaction!(set_authorized_client).set_on_start())
                    .register_transaction(hdb_repeat_bytes_v2(config.hash_count)),
                ApiVersion::Api3 => scenario!("6.HDBRepeatBytes")
                    .register_transaction(transaction!(set_authorized_client).set_on_start())
                    .register_transaction(hdb_repeat_bytes_v3(config.hash_count)),
                ApiVersion::Api4 => scenario!("6.HDBRepeatBytes")
                    .register_transaction(transaction!(set_authorized_client).set_on_start())
                    .register_transaction(hdb_repeat_bytes_v4(config.hash_count)),
            })
            .register_scenario(match **api_version {
                ApiVersion::Api1 => scenario!("7.KSRepeatBytes")
                    .register_transaction(ks_repeat_bytes_v1(config.hash_count)),
                ApiVersion::Api2 => scenario!("7.KSRepeatBytes")
                    .register_transaction(
                        transaction!(set_authorized_client_with_keyserver_ids).set_on_start(),
                    )
                    .register_transaction(ks_repeat_bytes_v2(config.hash_count)),
                ApiVersion::Api3 => scenario!("7.KSRepeatBytes")
                    .register_transaction(
                        transaction!(set_authorized_client_with_keyserver_ids).set_on_start(),
                    )
                    .register_transaction(ks_repeat_bytes_v3(config.hash_count)),
                ApiVersion::Api4 => scenario!("7.KSRepeatBytes")
                    .register_transaction(
                        transaction!(set_authorized_client_with_keyserver_ids).set_on_start(),
                    )
                    .register_transaction(ks_repeat_bytes_v4(config.hash_count)),
            })
            .set_default(GooseDefault::Host, host.as_str())?
            .set_default(GooseDefault::RunTime, 120)?
            .set_default(GooseDefault::Users, 5)?
            .set_default(GooseDefault::TransactionFormat, Csv)?
            .set_default(GooseDefault::ScenarioFormat, Csv)?
            .set_default(GooseDefault::ErrorFormat, Csv)?
            .set_default(GooseDefault::DebugFormat, Csv)?
            .set_default(
                GooseDefault::ReportFile,
                format!("{}-report.html", &log_base).as_str(),
            )?
            .set_default(
                GooseDefault::TransactionLog,
                format!("{}-transaction.csv", &log_base).as_str(),
            )?
            .set_default(
                GooseDefault::ScenarioLog,
                format!("{}-scenario.csv", &log_base).as_str(),
            )?
            .set_default(
                GooseDefault::ErrorLog,
                format!("{}-err.csv", &log_base).as_str(),
            )?
            .set_default(
                GooseDefault::DebugLog,
                format!("{}-debug.csv", &log_base).as_str(),
            )?
            .execute()
            .await?;

        if config.nmon_enabled {
            println!("Stopping NMON pid: '{}'", &nmon_pid);
            stop_nmon(&nmon_pid);
        }

        let mt = extract_goose_metrics(&goose_instance, &config);
        metrics.insert(test.clone(), mt);

        // there is no good way to fish this out of the Goose config
        // when running this framework it is expected that the operator specifies -- --scenarios <EXACTlY 1>
        // If we ever changed the way we run the framework, we would have to fix this
        scenario_name = goose_instance
            .scenarios
            .iter()
            .find(|&sc| !sc.users.is_empty())
            .map(|sc| sc.name.clone())
            .context("no scenario specified")?;

        // user count can be overriden by `-u` of the Goose config
        // We want to push this info to our stats collectors (Prometheus)
        user_count = goose_instance.total_users;
    }

    if !ids.is_empty() {
        println!("Stopping containers...");
        for id in ids {
            stop_container(&id).await;
        }
    }

    if let Some(n_id) = &network_id {
        destroy_network(n_id).await?;
    }

    // Rehash timestamps/metrics
    if config.nmon_enabled && config.comparison_mode == ComparisonMode::Compare {
        process_nmon(
            format!("{}-{}{}", "baseline", timestamp, ".nmon"),
            format!("{}-{}{}", "new", timestamp, ".nmon"),
        );
    }

    // Run the analyzer on the results directory
    println!("Running analyzer on results directory: {timestamp}");

    let results_dir = Path::new("results");

    print_metrics_comparison(
        results_dir.join(timestamp.to_string()),
        metrics.get("baseline").unwrap(),
        metrics.get("new"),
        scenario_name,
        user_count,
        &config,
    )?;

    Ok(())
}
