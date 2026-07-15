// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, crate_version};
use serde::Deserialize;

use minhttp::mpserver::{cli::ServerConfigSource, traits::RelativeConfig};
use shared_types::FriendlyDuration;

#[derive(Debug, Parser)]
#[clap(
    name = "hdbserver",
    about = concat!("SecureDNA HDB Server ", crate_version!()),
    version = crate_version!(),
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
        env = "SECUREDNA_HDBSERVER_YUBICO_API_SECRET_KEY",
        hide_env_values = true
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
        help = "Size limit for window/hash bodies in SCEP.",
        env = "SECUREDNA_HDBSERVER_SCEP_HASH_LIMIT",
        default_value_t = Config::default_scep_hash_limit()
    )]
    #[serde(default = "Config::default_scep_hash_limit")]
    pub scep_hash_limit: u64,

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
        help = "Path to the database's verification token and certificate chain bundle file, used for verifiable screening",
        env = "SECUREDNA_HDBSERVER_VERIFIER_TOKEN_FILE"
    )]
    pub verifier_token_file: Option<PathBuf>,

    #[clap(
        long,
        help = "Path to the database's .priv verification keypair file, used for verifiable screening",
        env = "SECUREDNA_HDBSERVER_VERIFIER_KEYPAIR_FILE"
    )]
    pub verifier_keypair_file: Option<PathBuf>,

    #[clap(
        long,
        help = "The file containing the passphrase to decrypt the database's .priv verification keypair file (--verifier-keypair-file)",
        env = "SECUREDNA_HDBSERVER_VERIFIER_KEYPAIR_PASSPHRASE_FILE"
    )]
    pub verifier_keypair_passphrase_file: Option<PathBuf>,

    #[clap(
        long,
        help = "Path to the TOTP certificate bundle",
        env = "SECUREDNA_HDBSERVER_TOTP_CERT_FILE"
    )]
    pub totp_cert_file: PathBuf,

    #[clap(
        long,
        help = "The file containing the access password to talk to the TOTP server",
        env = "SECUREDNA_HDBSERVER_TOTP_ACCESS_PASSPHRASE_FILE"
    )]
    pub totp_access_passphrase_file: PathBuf,

    #[clap(
        long,
        help = "The URL to the verifiable screening public key history that will be signed into verifiable screening responses.",
        env = "SECUREDNA_HDBSERVER_VERIFIER_HISTORY_URL",
        default_value = "https://github.com/SecureDNA/verifiable-screening"
    )]
    pub verifier_history_url: Option<String>,

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

    #[clap(
        long,
        help = "Path to a file containing an smtp2go API key used to send audit email. If unset, sending audit email is disabled.",
        env = "SECUREDNA_HDBSERVER_AUDIT_SMTP2GO_API_KEY_FILE"
    )]
    pub audit_smtp2go_api_key_file: Option<PathBuf>,

    #[clap(
        long,
        help = "The TOML template file used when sending audit email. See ../audit-email-template.toml for an example.",
        env = "SECUREDNA_HDBSERVER_AUDIT_TEMPLATE_FILE"
    )]
    pub audit_template_file: Option<PathBuf>,

    #[clap(
        long,
        help = "The time after which the server will disable keepalive for incoming connections.",
        env = "SECUREDNA_HDBSERVER_SOFT_TIMEOUT"
    )]
    pub soft_timeout: Option<FriendlyDuration>,

    #[clap(
        long,
        help = "The time after which the server will kill incoming connections.",
        env = "SECUREDNA_HDBSERVER_HARD_TIMEOUT"
    )]
    pub hard_timeout: Option<FriendlyDuration>,

    #[clap(
        long,
        help = "For screening/exemption requests, how many hashes it takes to extend the timeouts by a second.",
        env = "SECUREDNA_HDBSERVER_HASHES_PER_SEC_TIMEOUT"
    )]
    pub hashes_per_sec_timeout: Option<NonZeroU64>,
}

// Note: If you change these, remember to update example-config.toml in the crate root
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
        100_000
    }

    pub fn default_scep_hash_limit() -> u64 {
        100_000_000
    }

    pub fn default_et_size_limit() -> u64 {
        100_000
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
        self.verifier_token_file = self.verifier_token_file.map(|p| base.join(p));
        self.verifier_keypair_file = self.verifier_keypair_file.map(|p| base.join(p));
        self.verifier_keypair_passphrase_file =
            self.verifier_keypair_passphrase_file.map(|p| base.join(p));
        self.totp_cert_file = base.join(self.totp_cert_file);
        self.totp_access_passphrase_file = base.join(self.totp_access_passphrase_file);
        if self.event_store_path != Path::new(":memory:") {
            self.event_store_path = base.join(self.event_store_path);
        }
        self.audit_smtp2go_api_key_file = self.audit_smtp2go_api_key_file.map(|p| base.join(p));
        self.audit_template_file = self.audit_template_file.map(|p| base.join(p));
        self
    }
}
