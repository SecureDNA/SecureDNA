// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::{Path, PathBuf};

use clap::{crate_version, ArgAction, Args, Parser};
use serde::Deserialize;

use doprf::active_security::Commitment;
use doprf::party::KeyserverId;
use doprf::prf::KeyShare;
use minhttp::mpserver::{cli::ServerConfigSource, traits::RelativeConfig};

#[derive(Debug, Parser)]
#[clap(
    name = "keyserver",
    about = "SecureDNA DOPRF Key Server",
    version = crate_version!()
)]
pub struct Opts {
    #[command(flatten)]
    pub config: ServerConfigSource<Config>,
}

#[derive(Clone, Debug, Args, Deserialize)]
pub struct Config {
    #[clap(
        long,
        env = "SECUREDNA_KEYSERVER_ID",
        help = "The id of the keyserver. Corresponds to the x coordinate of its keyshare"
    )]
    pub id: KeyserverId,

    #[clap(
        long,
        env = "SECUREDNA_KEYSERVER_KEYHOLDERS_REQUIRED",
        help = "The number of keyholders required to hash a value"
    )]
    pub keyholders_required: u32,

    #[clap(
        short,
        long,
        env = "SECUREDNA_KEYSERVER_KEYSHARE",
        help = "The keyshare, as a hexadecimal string."
    )]
    pub keyshare: KeyShare,

    #[clap(
        long,
        action = ArgAction::Set,
        value_delimiter = ',',
        env = "SECUREDNA_KEYSERVER_ACTIVE_SECURITY_KEY",
        help = "List of commitments comprising the active security key",
    )]
    pub active_security_key: Vec<Commitment>,

    #[clap(
        long,
        help = "Maximum simultaneous hashing/encryption requests before 503 unavailable is returned",
        default_value_t = Config::default_max_heavy_clients(),
        env = "SECUREDNA_KEYSERVER_MAX_HEAVY_CLIENTS"
    )]
    #[serde(default = "Config::default_max_heavy_clients")]
    pub max_heavy_clients: usize,

    #[clap(
        long,
        help = "Maximum simultaneous queries to encrypt in parallel across server",
        env = "SECUREDNA_KEYSERVER_CRYPTO_PARALLELISM_PER_SERVER"
    )]
    pub crypto_parallelism_per_server: Option<usize>,

    #[clap(
        long,
        help = "Size of query queue per request",
        env = "SECUREDNA_KEYSERVER_CRYPTO_PARALLELISM_PER_REQUEST"
    )]
    pub crypto_parallelism_per_request: Option<usize>,

    #[clap(
        long,
        help = "Size limit for JSON request bodies in SCEP",
        env = "SECUREDNA_KEYSERVER_SCEP_JSON_SIZE_LIMIT",
        default_value_t = Config::default_scep_json_size_limit(),
    )]
    #[serde(default = "Config::default_scep_json_size_limit")]
    pub scep_json_size_limit: u64,

    #[clap(
        long,
        help = "Directory containing manufacturer root certs for SCEP client cert verification",
        env = "SECUREDNA_KEYSERVER_MANUFACTURER_ROOTS"
    )]
    pub manufacturer_roots: PathBuf,

    #[clap(
        long,
        help = "Path to certificate revocation list TOML file",
        env = "SECUREDNA_KEYSERVER_REVOCATION_LIST"
    )]
    pub revocation_list: Option<PathBuf>,

    #[clap(
        long,
        help = "Path to the server's token and certificate chain bundle file, used for SCEP",
        env = "SECUREDNA_KEYSERVER_TOKEN_FILE"
    )]
    pub token_file: PathBuf,

    #[clap(
        long,
        help = "Path to the server's .priv keypair file, used for SCEP",
        env = "SECUREDNA_KEYSERVER_KEYPAIR_FILE"
    )]
    pub keypair_file: PathBuf,

    #[clap(
        long,
        help = "The file containing the passphrase to decrypt the server's .priv keypair file (--keypair-file)",
        env = "SECUREDNA_KEYSERVER_KEYPAIR_PASSPHRASE_FILE"
    )]
    pub keypair_passphrase_file: PathBuf,

    #[clap(
        long,
        help = "Do not set the `secure` flag on session cookies, allowing them to be transported over http://. This is useful for local testing.",
        env = "SECUREDNA_KEYSERVER_ALLOW_INSECURE_COOKIE",
        default_value_t = false
    )]
    #[serde(default)]
    pub allow_insecure_cookie: bool,

    #[clap(
        long,
        help = "Writable path where the server can persist event store data (ratelimits, client versions, etc). The default is :memory:, which is an in-memory store that will be erased on shutdown.",
        env = "SECUREDNA_KEYSERVER_EVENT_STORE_PATH",
        default_value_os_t = Config::default_event_store_path()
    )]
    #[serde(default = "Config::default_event_store_path")]
    pub event_store_path: PathBuf,
}

// Note: If you change these, remember to update example-config.toml in the crate root
impl Config {
    pub fn default_max_heavy_clients() -> usize {
        512
    }

    pub fn default_scep_json_size_limit() -> u64 {
        100000
    }

    pub fn default_event_store_path() -> PathBuf {
        ":memory:".into()
    }
}

impl RelativeConfig for Config {
    fn relative_to(mut self, base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
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
