// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::{Path, PathBuf};

use clap::{crate_version, Args, Parser};
use serde::Deserialize;

use minhttp::mpserver::{cli::ServerConfigSource, traits::RelativeConfig};

#[derive(Debug, Parser)]
#[clap(
    name = "hdbserver",
    about = "SecureDNA HDB Server",
    version = crate_version!()
)]
pub struct Opts {
    #[command(flatten)]
    pub config: ServerConfigSource<Config>,
}

#[derive(Clone, Debug, Args, Deserialize)]
pub struct Config {
    #[clap(
        help = "Where to find the database",
        env = "SECUREDNA_HDBSERVER_DATABASE"
    )]
    pub database: PathBuf,

    #[clap(
        long,
        help = "Maximum simultaneous HDB query requests before 503 unavailable is returned",
        default_value_t = Config::default_max_heavy_clients(),
        env = "SECUREDNA_HDBSERVER_MAX_HEAVY_CLIENTS"
    )]
    #[serde(default = "Config::default_max_heavy_clients")]
    pub max_heavy_clients: usize,

    #[clap(
        long,
        help = "Maximum parallel HDB queries",
        default_value_t = Config::default_disk_parallelism_per_server(),
        env = "SECUREDNA_HDBSERVER_MAX_DISK_PARALLELISM_PER_SERVER"
    )]
    #[serde(default = "Config::default_disk_parallelism_per_server")]
    pub disk_parallelism_per_server: usize,

    #[clap(
        long,
        help = "Size of query queue per request",
        default_value_t = Config::default_disk_parallelism_per_request(),
        env = "SECUREDNA_HDBSERVER_MAX_DISK_PARALLELISM_PER_REQUEST"
    )]
    #[serde(default = "Config::default_disk_parallelism_per_request")]
    pub disk_parallelism_per_request: usize,

    #[clap(
        long,
        help = "Path to a JSON file describing a hash spec",
        env = "SECUREDNA_HDBSERVER_HASH_SPEC_PATH"
    )]
    pub hash_spec_path: Option<PathBuf>,

    #[clap(
        long,
        help = "Yubico API client ID. This is a short digit string, used to verify YubiKey OTPs when handling an order with a 2FA-enabled exemption. If set to the string 'allow_all', all YubiKey OTPs are treated as valid.",
        env = "SECUREDNA_HDBSERVER_YUBICO_API_CLIENT_ID"
    )]
    pub yubico_api_client_id: Option<String>,

    #[clap(
        long,
        help = "Yubico API secret key. This is a base-64 string, used to verify YubiKey OTPs when handling an order with a 2FA-enabled exemption.",
        env = "SECUREDNA_HDBSERVER_YUBICO_API_SECRET_KEY"
    )]
    pub yubico_api_secret_key: Option<String>,

    #[clap(
        long,
        help = "Size limit for JSON request bodies in SCEP",
        env = "SECUREDNA_HDBSERVER_SCEP_JSON_SIZE_LIMIT",
        default_value_t = Config::default_scep_json_size_limit()
    )]
    #[serde(default = "Config::default_scep_json_size_limit")]
    pub scep_json_size_limit: u64,

    #[clap(
        long,
        help = "Size limit for exemption tokens",
        env = "SECUREDNA_HDBSERVER_ELT_SIZE_LIMIT",
        default_value_t = Config::default_et_size_limit()
    )]
    #[serde(default = "Config::default_et_size_limit")]
    pub et_size_limit: u64,

    #[clap(
        long,
        help = "Directory containing exemption root certs for exemption token chain verification",
        env = "SECUREDNA_HDBSERVER_EXEMPTION_ROOTS"
    )]
    pub exemption_roots: PathBuf,

    #[clap(
        long,
        help = "Directory containing manufacturer root certs for SCEP client cert verification",
        env = "SECUREDNA_HDBSERVER_MANUFACTURER_ROOTS"
    )]
    pub manufacturer_roots: PathBuf,

    #[clap(
        long,
        help = "Path to certificate revocation list TOML file",
        env = "SECUREDNA_HDBSERVER_REVOCATION_LIST"
    )]
    pub revocation_list: Option<PathBuf>,

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
    #[serde(default)]
    pub allow_insecure_cookie: bool,

    #[clap(
        long,
        help = "Writable path where the server can persist event store data (ratelimits, client versions, etc). The default is :memory:, which is an in-memory store that will be erased on shutdown.",
        env = "SECUREDNA_HDBSERVER_EVENT_STORE_PATH",
        default_value_os_t = Config::default_event_store_path()
    )]
    #[serde(default = "Config::default_event_store_path")]
    pub event_store_path: PathBuf,
}

impl Config {
    pub fn default_max_heavy_clients() -> usize {
        512
    }

    pub fn default_disk_parallelism_per_server() -> usize {
        4096
    }

    pub fn default_disk_parallelism_per_request() -> usize {
        256
    }

    pub fn default_scep_json_size_limit() -> u64 {
        100000
    }

    pub fn default_et_size_limit() -> u64 {
        100000
    }

    pub fn default_event_store_path() -> PathBuf {
        ":memory:".into()
    }
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

impl RelativeConfig for Config {
    fn relative_to(mut self, base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        self.database = base.join(self.database);
        self.hash_spec_path = self.hash_spec_path.map(|p| base.join(p));
        self.exemption_roots = base.join(self.exemption_roots);
        self.manufacturer_roots = base.join(self.manufacturer_roots);
        self.revocation_list = self.revocation_list.map(|p| base.join(p));
        self.token_file = base.join(self.token_file);
        self.keypair_file = base.join(self.keypair_file);
        self.keypair_passphrase_file = base.join(self.keypair_passphrase_file);
        if self.event_store_path != Path::new(":memory:") {
            self.event_store_path = base.join(self.event_store_path);
        }
        self
    }
}
