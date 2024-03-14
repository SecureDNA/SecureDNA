// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use kiss_docker::container::Container;
use kiss_docker::network::{list_networks, rm_network, Network};
use std::collections::HashMap;
use std::fmt::Write;
use std::time::Duration;
use tokio::time::sleep;

use crate::shared::config::{
    ClientsConfig, ComparisonMode, Config, HdbServersConfig, KeyServersConfig,
};

pub async fn check_running_containers_and_kill(image: &str) -> anyhow::Result<()> {
    let running = kiss_docker::container::list_all(Some(image)).await?;
    if !running.is_empty() {
        println!("Unexpected running containers. Killing...");
        for process in running {
            println!(
                "Killing container {} with image {}...",
                process.id, process.image
            );
            kiss_docker::container::stop_and_rm_container(&process.id).await?;
        }
    }

    Ok(())
}

pub async fn create_network(config: &Config) -> anyhow::Result<String> {
    println!("Creating test network...");

    let networks = list_networks().await?;

    let network_id =
        if let Some(network) = networks.iter().find(|nw| nw.name == config.network_name) {
            network.id.clone()
        } else {
            Network {
                name: &config.network_name,
                ..Default::default()
            }
            .create()
            .await?
        };

    Ok(network_id)
}

pub async fn destroy_network(network_id: &str) -> anyhow::Result<()> {
    println!("Destroy test network...");

    rm_network(network_id).await?;

    Ok(())
}

pub async fn start_keyservers(
    config: &KeyServersConfig,
    comparison_mode: &ComparisonMode,
    network_id: &str,
) -> anyhow::Result<Vec<String>> {
    println!("Checking keyservers...");
    check_running_containers_and_kill(&config.keyserver_repo_base).await?;

    if *comparison_mode == ComparisonMode::Compare {
        check_running_containers_and_kill(&config.keyserver_repo_new).await?;
    }

    println!("Starting keyserver...");

    if *comparison_mode == ComparisonMode::Compare {
        println!(
            "Starting with ports: {}, {}",
            config.keyserver_port,
            config.keyserver_port + 1
        );
    } else {
        println!("Starting with port: {}", config.keyserver_port);
    }

    let mut ids: Vec<String> = vec![];

    let flags = match &config.keyserver_cpu_limit {
        None => HashMap::new(),
        Some(limit) => HashMap::from([("--cpus".to_string(), limit.clone())]),
    };

    let env = HashMap::from([
        // current
        (
            "SECUREDNA_KEYSERVER_KEYSHARE".to_owned(),
            config.keyserver_keyshare.clone(),
        ),
        (
            "SECUREDNA_KEYSERVER_ID".to_owned(),
            config.keyserver_id.to_string(),
        ),
        (
            "SECUREDNA_KEYSERVER_KEYHOLDERS_REQUIRED".to_owned(),
            "1".to_owned(),
        ),
        (
            "SECUREDNA_KEYSERVER_ACTIVE_SECURITY_KEY".to_owned(),
            config.keyserver_active_security_key.clone(),
        ),
        // backwards compatibility
        (
            "SECUREDNA_KEYSHARE".to_owned(),
            config.keyserver_keyshare.clone(),
        ),
        ("SECUREDNA_KEYSERVER_IDS".to_string(), "1".to_owned()),
        ("SECUREDNA_KEYSERVERS".to_string(), "1".to_owned()),
    ]);

    let id = Container {
        repo: &config.keyserver_repo_base,
        tag: &config.keyserver_tag_base,
        env: env.clone(),
        flags: flags.clone(),
        port_expose: config.keyserver_port,
        port_internal: config.keyserver_port_internal_base,
        norm: true,
        network: Some(network_id),
        name: Some("securedna-keyserver-base"),
        ..Default::default()
    }
    .start()
    .await?;
    ids.push(id);

    if *comparison_mode == ComparisonMode::Compare {
        let id2 = Container {
            repo: &config.keyserver_repo_new,
            tag: &config.keyserver_tag_new,
            env,
            flags,
            port_expose: config.keyserver_port + 1,
            port_internal: config.keyserver_port_internal_new,
            network: Some(network_id),
            name: Some("securedna-keyserver-new"),
            ..Default::default()
        }
        .start()
        .await?;
        ids.push(id2);
    }

    Ok(ids)
}

pub async fn start_hdbservers(
    config: &HdbServersConfig,
    comparison_mode: &ComparisonMode,
    network_id: &str,
) -> anyhow::Result<Vec<String>> {
    println!("Checking HDB servers...");
    check_running_containers_and_kill(&config.hdb_repo_base).await?;

    if *comparison_mode == ComparisonMode::Compare {
        check_running_containers_and_kill(&config.hdb_repo_new).await?;
    }

    println!("Starting HDB servers...");

    if *comparison_mode == ComparisonMode::Compare {
        println!(
            "Starting with ports: {}, {}",
            config.hdb_port,
            config.hdb_port + 1
        );
    } else {
        println!("Starting with port: {}", config.hdb_port,);
    }
    let mut ids: Vec<String> = vec![];

    let volumes = vec![config.hdb_vol.as_str()];

    let flags = match &config.hdb_cpu_limit {
        None => HashMap::new(),
        Some(limit) => HashMap::from([("--cpus".to_string(), limit.clone())]),
    };

    let id = Container {
        repo: &config.hdb_repo_base,
        tag: &config.hdb_tag_base,
        volumes: &volumes,
        port_expose: config.hdb_port,
        port_internal: config.hdb_port_internal_base,
        flags: flags.clone(),
        network: Some(network_id),
        name: Some("securedna-hdbserver-base"),
        norm: true,
        ..Default::default()
    }
    .start()
    .await?;
    ids.push(id);

    if *comparison_mode == ComparisonMode::Compare {
        let id2 = Container {
            repo: &config.hdb_repo_new,
            tag: &config.hdb_tag_new,
            volumes: &volumes,
            port_expose: config.hdb_port + 1,
            port_internal: config.hdb_port_internal_new,
            network: Some(network_id),
            name: Some("securedna-hdbserver-new"),
            flags,
            ..Default::default()
        }
        .start()
        .await?;
        ids.push(id2);
    }

    // give enough time to the HDB server to come up
    sleep(Duration::from_secs(2)).await;

    Ok(ids)
}

pub async fn start_synthclient(
    config: &ClientsConfig,
    comparison_mode: &ComparisonMode,
    network_id: &str,
) -> anyhow::Result<Vec<String>> {
    println!("Checking synthclients...");
    check_running_containers_and_kill(&config.client_repo_base).await?;

    if *comparison_mode == ComparisonMode::Compare {
        check_running_containers_and_kill(&config.client_repo_new).await?;
    }

    println!("Starting synthclient...");

    if *comparison_mode == ComparisonMode::Compare {
        println!(
            "Starting with ports: {}, {}",
            config.client_port,
            config.client_port + 1
        );
    } else {
        println!("Starting with port: {}", config.client_port);
    }
    let mut ids: Vec<String> = vec![];

    let flags = match &config.client_cpu_limit {
        None => HashMap::new(),
        Some(limit) => HashMap::from([("--cpus".to_string(), limit.clone())]),
    };

    let mut env_base = HashMap::new();
    let mut env_new = HashMap::new();

    assert!(!config.client_keyservers.is_empty());
    if config.client_keyservers[0] != "<keyserver>" {
        let client_keyservers = config.client_keyservers.join(",");

        let mut enumerations = vec![];
        for (idx, server) in config.client_keyservers.iter().enumerate() {
            let with_index = format!("{}:{}", idx + 1, server);
            enumerations.push(with_index);
        }
        let with_urls = enumerations.join(",");

        let env = HashMap::from([
            (
                "SECUREDNA_SYNTHCLIENT_KEYSERVER_IDS_URLS".to_owned(),
                with_urls,
            ),
            (
                "SECUREDNA_SYNTHCLIENT_KEYSERVER_DOMAINS".to_owned(),
                client_keyservers,
            ),
        ]);

        env_base.extend(env.clone());
        env_new.extend(env);
    } else {
        env_base.extend([
            (
                "SECUREDNA_SYNTHCLIENT_KEYSERVER_IDS_URLS".to_owned(),
                "1:http://securedna-keyserver-base".to_owned(),
            ),
            (
                "SECUREDNA_SYNTHCLIENT_KEYSERVER_DOMAINS".to_owned(),
                "securedna-keyserver-base".to_owned(),
            ),
            (
                "SECUREDNA_SYNTHCLIENT_USE_HTTP".to_owned(),
                "true".to_owned(),
            ),
        ]);
        env_new.extend([
            (
                "SECUREDNA_SYNTHCLIENT_KEYSERVER_IDS_URLS".to_owned(),
                "1:http://securedna-keyserver-new".to_owned(),
            ),
            (
                "SECUREDNA_SYNTHCLIENT_KEYSERVER_DOMAINS".to_owned(),
                "securedna-keyserver-new".to_owned(),
            ),
            (
                "SECUREDNA_SYNTHCLIENT_USE_HTTP".to_owned(),
                "true".to_owned(),
            ),
        ])
    }

    assert_eq!(config.client_hdbservers.len(), 1);
    if config.client_hdbservers[0] != "<hdbserver>" {
        let hdb_server = config.client_hdbservers[0].clone();

        let env = HashMap::from([
            (
                "SECUREDNA_SYNTHCLIENT_HDBSERVER".to_owned(),
                hdb_server.clone(),
            ),
            ("SECUREDNA_SYNTHCLIENT_HDB_DOMAINS".to_owned(), hdb_server),
        ]);
        env_base.extend(env.clone());
        env_new.extend(env);
    } else {
        env_base.extend([
            (
                "SECUREDNA_SYNTHCLIENT_HDBSERVER".to_owned(),
                "http://securedna-hdbserver-base".to_owned(),
            ),
            (
                "SECUREDNA_SYNTHCLIENT_HDB_DOMAINS".to_owned(),
                "securedna-hdbserver-base".to_owned(),
            ),
        ]);
        env_new.extend([
            (
                "SECUREDNA_SYNTHCLIENT_HDBSERVER".to_owned(),
                "http://securedna-hdbserver-new".to_owned(),
            ),
            (
                "SECUREDNA_SYNTHCLIENT_HDB_DOMAINS".to_owned(),
                "securedna-hdbserver-new".to_owned(),
            ),
        ]);
    }

    let ops = match &config.client_override_ops {
        None => {
            vec!["./synthclient"]
        }
        Some(explicit_override) => {
            let mut o = vec!["./synthclient"];
            for oride in explicit_override {
                o.push(oride.as_str());
            }
            o
        }
    };

    let id = Container {
        repo: &config.client_repo_base,
        tag: &config.client_tag_base,
        port_expose: config.client_port,
        ops: &ops,
        port_internal: config.client_port_internal_base,
        env: env_base,
        flags: flags.clone(),
        network: Some(network_id),
        name: Some("securedna-client-base"),
        norm: true,
        ..Default::default()
    }
    .start()
    .await?;
    ids.push(id);

    if *comparison_mode == ComparisonMode::Compare {
        let id2 = Container {
            repo: &config.client_repo_new,
            tag: &config.client_tag_new,
            port_expose: config.client_port + 1,
            ops: &ops,
            port_internal: config.client_port_internal_new,
            network: Some(network_id),
            name: Some("securedna-client-new"),
            env: env_new,
            flags,
            ..Default::default()
        }
        .start()
        .await?;
        ids.push(id2);
    }

    Ok(ids)
}

pub async fn show_running() -> String {
    kiss_docker::container::list_running(Some("ghcr.io/securedna"))
        .await
        .unwrap()
        .iter()
        .fold(String::new(), |mut output, container| {
            let _ = write!(output, "{container:?}");
            output
        })
}

pub async fn stop_container(id: &str) {
    kiss_docker::container::stop_container(id).await.unwrap()
}
