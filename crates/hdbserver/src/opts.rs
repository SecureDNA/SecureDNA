// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use clap::{crate_version, Parser};

#[derive(Debug, Parser)]
#[clap(
    name = "hdbserver",
    about = "SecureDNA HDB Server",
    version = crate_version!()
)]
pub struct Opts {
    #[clap(
        help = "Where to find the database",
        env = "SECUREDNA_HDBSERVER_DATABASE"
    )]
    pub database: PathBuf,

    #[clap(
        short,
        long,
        help = "Port to listen on.",
        default_value = "80",
        env = "SECUREDNA_HDBSERVER_PORT"
    )]
    pub port: u16,

    #[clap(
        short,
        long,
        help = "Port to listen on for monitoring plane.",
        env = "SECUREDNA_HDBSERVER_MONITORING_PLANE_PORT"
    )]
    pub monitoring_plane_port: Option<u16>,

    #[clap(
        long,
        help = "Maximum simultaneously connected clients before connections are no longer accepted",
        default_value = "1024",
        env = "SECUREDNA_HDBSERVER_MAX_CLIENTS"
    )]
    pub max_clients: usize,

    #[clap(
        long,
        help = "Maximum simultaneously connected monitoring plane clients before connections are no longer accepted",
        default_value = "1024",
        env = "SECUREDNA_HDBSERVER_MAX_MONITORING_PLANE_CLIENTS"
    )]
    pub max_monitoring_plane_clients: usize,

    #[clap(
        long,
        help = "Maximum simultaneous HDB query requests before 503 unavailable is returned",
        default_value = "512",
        env = "SECUREDNA_HDBSERVER_MAX_HEAVY_CLIENTS"
    )]
    pub max_heavy_clients: usize,

    #[clap(
        long,
        help = "Maximum parallel HDB queries",
        default_value = "4096",
        env = "SECUREDNA_HDBSERVER_MAX_DISK_PARALLELISM_PER_SERVER"
    )]
    pub disk_parallelism_per_server: usize,

    #[clap(
        long,
        help = "Size of query queue per request",
        default_value = "256",
        env = "SECUREDNA_HDBSERVER_MAX_DISK_PARALLELISM_PER_REQUEST"
    )]
    pub disk_parallelism_per_request: usize,

    #[clap(
        long,
        help = "Path to a JSON file describing a hash spec",
        env = "SECUREDNA_HDBSERVER_HASH_SPEC_PATH"
    )]
    pub hash_spec_path: Option<PathBuf>,

    #[clap(
        long,
        help = "Yubico API client ID. This is a short digit string, used to verify YubiKey OTPs when handling an order with a 2FA-enabled exemption list.",
        env = "SECUREDNA_HDBSERVER_YUBICO_API_CLIENT_ID"
    )]
    pub yubico_api_client_id: Option<String>,

    #[clap(
        long,
        help = "Yubico API secret key. This is a base-64 string, used to verify YubiKey OTPs when handling an order with a 2FA-enabled exemption list.",
        env = "SECUREDNA_HDBSERVER_YUBICO_API_SECRET_KEY"
    )]
    pub yubico_api_secret_key: Option<String>,

    #[clap(
        long,
        help = "Size limit for JSON request bodies in SCEP",
        env = "SECUREDNA_HDBSERVER_SCEP_JSON_SIZE_LIMIT",
        default_value = "100000"
    )]
    pub scep_json_size_limit: u64,

    #[clap(
        long,
        help = "Directory containing manufacturer root certs for SCEP client cert verification",
        env = "SECUREDNA_HDBSERVER_MANUFACTURER_ROOTS"
    )]
    pub manufacturer_roots: PathBuf,

    #[clap(
        long,
        help = "Path to the database's token and certificate chain bundle file, used for SCEP",
        env = "SECUREDNA_HDBSERVER_TOKEN_FILE"
    )]
    pub token_file: PathBuf,

    #[clap(
        long,
        help = "Path to the database's .priv keypair file, used for SCEP",
        env = "SECUREDNA_HDBSERVER_KEYPAIR_FILE"
    )]
    pub keypair_file: PathBuf,

    #[clap(
        long,
        help = "The file containing the passphrase to decrypt the database's .priv keypair file (--keypair-file)",
        env = "SECUREDNA_HDBSERVER_KEYPAIR_PASSPHRASE_FILE"
    )]
    pub keypair_passphrase_file: PathBuf,

    #[clap(
        long,
        help = "Do not set the `secure` flag on session cookies, allowing them to be transported over http://. This is useful for local testing.",
        env = "SECUREDNA_HDBSERVER_ALLOW_INSECURE_COOKIE",
        default_value_t = false
    )]
    pub allow_insecure_cookie: bool,

    #[clap(
        long,
        help = "Writable path where the server can persist data for ratelimits. The default is :memory:, which is an in-memory store that will be erased on shutdown.",
        env = "SECUREDNA_HDBSERVER_PERSISTENCE_PATH",
        default_value = ":memory:"
    )]
    pub persistence_path: PathBuf,
}

pub const DEFAULT_HASH_SPEC: &str = r#"{
    "max_expansions_per_window": 10000,
    "htdv": [
        { "type": "dna", "width": 42, "direction": "CECH", "skiptype": "shingled" },
        { "type": "dna", "width": 30, "direction": "CECH", "skiptype": "shingled" },
        { "type": "aa", "width": 20, "direction": "FW", "skiptype": "shingled" },
        { "type": "aa", "width": 20, "direction": "RC", "skiptype": "shingled" }
    ]
}
"#;
