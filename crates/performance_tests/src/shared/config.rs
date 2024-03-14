// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

/* Configuration Management, we can not use clap here */

use anyhow::{anyhow, Context};
use std::env;
use std::fs::File;
use std::io::Read;

use crate::shared::types::HashCount;
use serde::{Deserialize, Serialize};
use serde_json;

fn get_default_hash_count() -> HashCount {
    HashCount::get_default()
}

fn get_port_80() -> usize {
    80
}

fn get_default_pushgateway() -> String {
    String::from("localhost:9091")
}

fn get_latest_tag() -> String {
    String::from("latest")
}

fn get_default_keyserver() -> String {
    String::from("ghcr.io/securedna/keyserver")
}

fn get_default_hdbserver() -> String {
    String::from("ghcr.io/securedna/hdbserver")
}

fn get_default_client() -> String {
    String::from("ghcr.io/securedna/client")
}

fn get_default_network_name() -> String {
    String::from("securedna-loadtest-network")
}

fn get_client_default_keyserver_domains_staging() -> Vec<String> {
    vec![
        String::from("1.ks.staging.securedna.org"),
        String::from("2.ks.staging.securedna.org"),
        String::from("3.ks.staging.securedna.org"),
    ]
}

fn get_client_default_hdbserver_domains_staging() -> Vec<String> {
    vec![String::from("1.db.staging.securedna.org")]
}

fn get_latest_api_version() -> ApiVersion {
    ApiVersion::Api4
}

fn get_default_comparison_mode() -> ComparisonMode {
    ComparisonMode::Compare
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyServersConfig {
    pub keyserver_port: usize,

    #[serde(default = "get_port_80")]
    pub keyserver_port_internal_base: usize,

    #[serde(default = "get_port_80")]
    pub keyserver_port_internal_new: usize,

    #[serde(default = "get_default_keyserver")]
    pub keyserver_repo_base: String,

    #[serde(default = "get_default_keyserver")]
    pub keyserver_repo_new: String,

    #[serde(default = "get_latest_tag")]
    pub keyserver_tag_base: String,

    #[serde(default = "get_latest_tag")]
    pub keyserver_tag_new: String,

    #[serde(default)]
    pub keyserver_cpu_limit: Option<String>,

    pub keyserver_keyshare: String,

    pub keyserver_id: u32,

    pub keyserver_active_security_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HdbServersConfig {
    pub hdb_port: usize,

    #[serde(default = "get_port_80")]
    pub hdb_port_internal_base: usize,

    #[serde(default = "get_port_80")]
    pub hdb_port_internal_new: usize,

    #[serde(default = "get_default_hdbserver")]
    pub hdb_repo_base: String,

    #[serde(default = "get_default_hdbserver")]
    pub hdb_repo_new: String,

    #[serde(default = "get_latest_tag")]
    pub hdb_tag_base: String,

    #[serde(default = "get_latest_tag")]
    pub hdb_tag_new: String,

    #[serde(default)]
    pub hdb_cpu_limit: Option<String>,

    pub hdb_vol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientsConfig {
    pub client_port: usize,

    #[serde(default = "get_port_80")]
    pub client_port_internal_base: usize,

    #[serde(default = "get_port_80")]
    pub client_port_internal_new: usize,

    #[serde(default = "get_default_client")]
    pub client_repo_base: String,

    #[serde(default = "get_default_client")]
    pub client_repo_new: String,

    #[serde(default = "get_latest_tag")]
    pub client_tag_base: String,

    #[serde(default = "get_latest_tag")]
    pub client_tag_new: String,

    #[serde(default = "get_client_default_hdbserver_domains_staging")]
    pub client_hdbservers: Vec<String>,

    #[serde(default = "get_client_default_keyserver_domains_staging")]
    pub client_keyservers: Vec<String>,

    #[serde(default)]
    pub client_cpu_limit: Option<String>,

    #[serde(default)]
    pub client_override_ops: Option<Vec<String>>,
}

#[derive(Copy, Debug, Clone, Serialize, Deserialize)]
pub enum ApiVersion {
    Api1 = 1,
    Api2 = 2,
    Api3 = 3,
    Api4 = 4,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonMode {
    Compare = 1,
    BaseOnly = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub url1: String,

    #[serde(default)]
    pub url2: String,

    #[serde(default = "get_default_comparison_mode")]
    pub comparison_mode: ComparisonMode,

    #[serde(default = "get_default_hash_count")]
    pub hash_count: HashCount,

    #[serde(default)]
    pub nmon_enabled: bool,

    #[serde(default)]
    pub keyservers: Option<KeyServersConfig>,

    #[serde(default)]
    pub hdbservers: Option<HdbServersConfig>,

    #[serde(default)]
    pub clients: Option<ClientsConfig>,

    #[serde(default)]
    pub auth_key: Option<String>,

    #[serde(default = "get_latest_api_version")]
    pub api_version_url1: ApiVersion,

    #[serde(default = "get_latest_api_version")]
    pub api_version_url2: ApiVersion,

    #[serde(default = "get_default_pushgateway")]
    pub pushgateway_url: String,

    #[serde(default = "get_default_network_name")]
    pub network_name: String,
}

pub fn load_config() -> anyhow::Result<Config> {
    let file_name =
        env::var("CONFIG").unwrap_or_else(|_| String::from("performance_tests/config.json"));

    let mut file =
        File::open(file_name).context("JSON file does not exist or could not be opened")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .context("Could not read or parse JSON file")?;

    let mut config: Config = serde_json::from_str(&contents)?;

    if config.url1.is_empty() {
        return Err(anyhow!("URL1 was not specified"));
    }

    if config.url2.is_empty() && config.comparison_mode == ComparisonMode::Compare {
        return Err(anyhow!("URL2 was not specified in comparison mode"));
    }

    if let Ok(hash_count) = env::var("SECUREDNA_HASH_COUNT") {
        let hash_count_usize: usize = hash_count.parse().unwrap();

        println!(
            "Overriding config.hash_count via env variable to {}",
            hash_count
        );
        config.hash_count = HashCount(hash_count_usize);
    }

    Ok(config)
}
