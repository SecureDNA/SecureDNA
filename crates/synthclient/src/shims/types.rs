// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use clap::{crate_version, ArgAction, Args, CommandFactory, Parser};
use serde::{de, Deserialize, Deserializer};
use tokio::sync::Mutex;
use url::Url;

use crate::parsefasta::{CurrentSystemLoadTracker, LimitConfiguration};
use crate::rate_limiter::{RateLimiter, SystemTimeHourProvider};
use crate::shims::event_store::Connection;
use doprf_client::server_selection::{ServerEnumerationSource, ServerSelector};
use minhttp::mpserver::{cli::ServerConfigSource, traits::RelativeConfig};
use scep_client_helpers::ClientCerts;
use shared_types::metrics::SynthClientMetrics;
use shared_types::server_selection::Tier;

#[derive(Debug, Parser)]
#[clap(
    name = "synthclient",
    about = "SecureDNA Synthesizer Client",
    version = crate_version!()
)]
pub struct Opts {
    #[command(flatten)]
    pub config: ServerConfigSource<Config>,
}

#[derive(Clone, Debug, Args, Deserialize)]
pub struct Config {
    #[command(flatten)]
    #[serde(flatten)]
    pub enumeration: EnumerationArgs,

    #[command(flatten)]
    #[serde(flatten)]
    pub selection_refresh: SelectionRefreshArgs,

    #[command(flatten)]
    #[serde(flatten)]
    pub certs: CertificateArgs,

    #[clap(
        long,
        help = "Memory limit in bytes",
        env = "SECUREDNA_SYNTHCLIENT_MEMORY_LIMIT"
    )]
    pub memorylimit: Option<usize>,

    #[clap(
        long,
        help = "By default, screening requests are limited to this many base pairs.",
        env = "SECUREDNA_SYNTHCLIENT_DEFAULT_MAX_REQUEST_BP",
        default_value_t = Config::default_default_max_request_bp(),
    )]
    #[serde(default = "Config::default_default_max_request_bp")]
    pub default_max_request_bp: usize,

    #[clap(
        long,
        help = "In a public demo setting, screening requests are limited to this many base pairs.",
        env = "SECUREDNA_SYNTHCLIENT_LIMITED_MAX_REQUEST_BP",
        default_value_t = Config::default_limited_max_request_bp(),
    )]
    #[serde(default = "Config::default_limited_max_request_bp")]
    pub limited_max_request_bp: usize,

    #[clap(
        long,
        help = "Secret key for validating reCAPTCHA v3 responses (enables a demo on https://securedna.org/)",
        env = "SECUREDNA_SYNTHCLIENT_RECAPTCHA_SECRET_KEY"
    )]
    pub recaptcha_secret_key: Option<String>,

    #[clap(
        long,
        help = "Hourly rate limit on reCAPTCHA screening requests from the same IP address",
        env = "SECUREDNA_SYNTHCLIENT_RECAPTCHA_REQUESTS_PER_HOUR",
        default_value_t = Config::default_recaptcha_requests_per_hour(),
    )]
    #[serde(default = "Config::default_recaptcha_requests_per_hour")]
    pub recaptcha_requests_per_hour: usize,

    #[clap(
        long,
        help = "Use http (instead of https) for all requests to internal servers (hdb and keyservers). Useful for local development, will not work with securedna.org servers.",
        env = "SECUREDNA_SYNTHCLIENT_USE_HTTP"
    )]
    pub use_http: bool,

    #[clap(
        long,
        help = "Redirect from / to this URL.",
        env = "SECUREDNA_FRONTEND_URL",
        default_value_t = Config::default_frontend_url(),
    )]
    #[serde(
        deserialize_with = "deserialize_via_parse",
        default = "Config::default_frontend_url"
    )]
    pub frontend_url: Url,

    #[clap(
        long,
        help = "Maximum size of JSON request bodies",
        env = "SECUREDNA_SYNTHCLIENT_JSON_SIZE_LIMIT",
        default_value_t = Config::default_json_size_limit(),
    )]
    #[serde(default = "Config::default_json_size_limit")]
    pub json_size_limit: u64,

    #[clap(
        long,
        help = "Writable path where synthclient can persist event store data (known server versions, etc). The default is :memory:, which is an in-memory store that will be erased on shutdown.",
        env = "SECUREDNA_SYNTHCLIENT_EVENT_STORE_PATH",
        default_value_os_t = Config::default_event_store_path(),
     )]
    #[serde(default = "Config::default_event_store_path")]
    pub event_store_path: PathBuf,
}

impl Config {
    fn default_default_max_request_bp() -> usize {
        1000000
    }

    fn default_limited_max_request_bp() -> usize {
        10000
    }

    fn default_recaptcha_requests_per_hour() -> usize {
        5
    }

    fn default_frontend_url() -> Url {
        "https://pages.securedna.org/web-interface/"
            .parse()
            .unwrap()
    }

    fn default_json_size_limit() -> u64 {
        100000
    }

    fn default_event_store_path() -> PathBuf {
        ":memory:".into()
    }
}

impl RelativeConfig for Config {
    fn relative_to(mut self, base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        self.certs = self.certs.relative_to(base);
        if self.event_store_path != Path::new(":memory:") {
            self.event_store_path = base.join(self.event_store_path);
        }
        self
    }
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct EnumerationArgs {
    #[clap(
        long,
        help = "Server tier to use for enumeration.",
        env = "SECUREDNA_SYNTHCLIENT_ENUMERATE_TIER",
        default_value_t = EnumerationArgs::default_enumerate_tier(),
     )]
    #[serde(default = "EnumerationArgs::default_enumerate_tier")]
    pub enumerate_tier: Tier,

    #[clap(
        long,
        help = "Apex domain to use for enumeration.",
        env = "SECUREDNA_SYNTHCLIENT_ENUMERATE_APEX",
        default_value_t = EnumerationArgs::default_enumerate_apex(),
     )]
    #[serde(default = "EnumerationArgs::default_enumerate_apex")]
    pub enumerate_apex: String,

    #[clap(
        long,
        help = "Domain of a DNS-over-HTTPS provider, e.g. `1.1.1.1`. If provided, DoH will be used for enumeration instead of native DNS.",
        env = "SECUREDNA_SYNTHCLIENT_DOH_PROVIDER"
    )]
    pub doh_provider: Option<String>,

    #[clap(
        long,
        action = ArgAction::Set,
        value_delimiter = ',',
        help = "Explicit keyserver domains to use, instead of enumerating. E.g. '1.ks.prod.securedna.org,2.ks.prod.securedna.org'. Requires --hdb-domains.",
        env = "SECUREDNA_SYNTHCLIENT_KEYSERVER_DOMAINS",
    )]
    pub keyserver_domains: Option<Vec<String>>,

    #[clap(
        long,
        action = ArgAction::Set,
        value_delimiter = ',',
        help = "Explicit hdb domains to use, instead of enumerating. E.g. '1.db.prod.securedna.org,2.db.prod.securedna.org'. Requires --keyserver-domains.",
        env = "SECUREDNA_SYNTHCLIENT_HDB_DOMAINS",
    )]
    pub hdb_domains: Option<Vec<String>>,
}

impl EnumerationArgs {
    fn default_enumerate_tier() -> Tier {
        "prod".into()
    }

    fn default_enumerate_apex() -> String {
        "securedna.org".to_owned()
    }

    /// Attempts to validate the provided enumeration arguments, exiting with an error if
    /// they aren't valid, and returns a enumeration source config
    pub fn validate_and_build(&self) -> ServerEnumerationSource {
        if self.keyserver_domains.is_some() != self.hdb_domains.is_some() {
            let mut cmd = Opts::command();
            cmd.error(
                clap::error::ErrorKind::ArgumentConflict,
                "If specifying domains explicitly, both keyserver and hdb domains must be provided."
            ).exit();
        }

        if self.keyserver_domains.is_some() {
            ServerEnumerationSource::Fixed {
                keyserver_domains: self.keyserver_domains.clone().unwrap(),
                hdb_domains: self.hdb_domains.clone().unwrap(),
            }
        } else if let Some(provider_domain) = &self.doh_provider {
            ServerEnumerationSource::DnsOverHttps {
                provider_domain: provider_domain.clone(),
                tier: self.enumerate_tier.clone(),
                apex: self.enumerate_apex.clone(),
            }
        } else {
            ServerEnumerationSource::NativeDns {
                tier: self.enumerate_tier.clone(),
                apex: self.enumerate_apex.clone(),
            }
        }
    }
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct SelectionRefreshArgs {
    #[clap(
        long,
        action = ArgAction::Set,
        help = "Timeout before a cached selection will be refreshed in the background. Uses formatting from the `humantime` crate.",
        env = "SECUREDNA_SYNTHCLIENT_SOFT_TIMEOUT",
        default_value_t = SelectionRefreshArgs::default_soft_timeout(),
     )]
    #[serde(
        default = "SelectionRefreshArgs::default_soft_timeout",
        deserialize_with = "deserialize_via_parse"
    )]
    pub soft_timeout: humantime::Duration,

    #[clap(
        long,
        action = ArgAction::Set,
        help = "Timeout before a cached selection will be refreshed in the _foreground_, making all requests wait. Uses formatting from the `humantime` crate.",
        env = "SECUREDNA_SYNTHCLIENT_BLOCKING_TIMEOUT",
        default_value_t = SelectionRefreshArgs::default_blocking_timeout(),
     )]
    #[serde(
        default = "SelectionRefreshArgs::default_blocking_timeout",
        deserialize_with = "deserialize_via_parse"
    )]
    pub blocking_timeout: humantime::Duration,

    #[clap(
        long,
        action = ArgAction::Set,
        help = "If nonzero, an extra amount of good keyservers, on top of the quorum threshold, below which the selection will be refreshed in the background.",
        env = "SECUREDNA_SYNTHCLIENT_SOFT_EXTRA_KS",
        default_value_t = SelectionRefreshArgs::default_soft_extra_keyserver_threshold(),
     )]
    #[serde(default = "SelectionRefreshArgs::default_soft_extra_keyserver_threshold")]
    pub soft_extra_keyserver_threshold: u32,

    #[clap(
        long,
        action = ArgAction::Set,
        help = "If nonzero, an extra amount of good hdbs, on top of the one needed for quorum, below which the selection will be refreshed in the background.",
        env = "SECUREDNA_SYNTHCLIENT_SOFT_EXTRA_HDB",
        default_value_t = SelectionRefreshArgs::default_soft_extra_hdb_threshold(),
     )]
    #[serde(default = "SelectionRefreshArgs::default_soft_extra_hdb_threshold")]
    pub soft_extra_hdb_threshold: u32,
}

impl SelectionRefreshArgs {
    fn default_soft_timeout() -> humantime::Duration {
        "1day".parse().unwrap()
    }

    fn default_blocking_timeout() -> humantime::Duration {
        "1week".parse().unwrap()
    }

    fn default_soft_extra_keyserver_threshold() -> u32 {
        1
    }

    fn default_soft_extra_hdb_threshold() -> u32 {
        1
    }
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct CertificateArgs {
    #[clap(
        long,
        help = "Path to your manufacturer token",
        env = "SECUREDNA_SYNTHCLIENT_TOKEN_FILE"
    )]
    pub token_file: PathBuf,

    #[clap(
        long,
        help = "Path to the .priv keypair file for your token.",
        env = "SECUREDNA_SYNTHCLIENT_KEYPAIR_FILE"
    )]
    pub keypair_file: PathBuf,

    #[clap(
        long,
        help = "The file containing the passphrase to decrypt the .priv keypair file (--keypair-file)",
        env = "SECUREDNA_SYNTHCLIENT_KEYPAIR_PASSPHRASE_FILE"
    )]
    pub keypair_passphrase_file: PathBuf,

    #[clap(
        long,
        help = "Use a test root when validating certificates.  This will never work against production servers.",
        env = "SECUREDNA_USE_TEST_ROOTS_DO_NOT_USE_THIS_IN_PROD"
    )]
    pub use_test_roots_do_not_use_this_in_prod: bool,
}

impl CertificateArgs {
    /// Attempts to validate the certificate args and load the client certificates,
    /// exiting with an error if the arguments are invalid.
    pub fn validate_and_build(&self) -> anyhow::Result<ClientCerts> {
        let passphrase = std::fs::read_to_string(&self.keypair_passphrase_file)
            .context("reading keypair passphrase file")?;
        let passphrase = passphrase.trim();

        if self.use_test_roots_do_not_use_this_in_prod {
            ClientCerts::load_with_test_roots(&self.token_file, &self.keypair_file, passphrase)
        } else {
            ClientCerts::load_with_prod_roots(&self.token_file, &self.keypair_file, passphrase)
        }
    }
}

impl RelativeConfig for CertificateArgs {
    fn relative_to(mut self, base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        self.token_file = base.join(self.token_file);
        self.keypair_file = base.join(self.keypair_file);
        self.keypair_passphrase_file = base.join(self.keypair_passphrase_file);
        self
    }
}

fn deserialize_via_parse<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    FromStr::from_str(&s).map_err(de::Error::custom)
}

pub struct SynthClientState {
    pub app_cfg: Config,
    pub is_serving_https: bool,
    pub server_selector: Arc<ServerSelector>,
    pub metrics: Option<Arc<SynthClientMetrics>>,
    pub limits: CurrentSystemLoadTracker,
    pub demo_rate_limiter: Mutex<RateLimiter<IpAddr, SystemTimeHourProvider>>,
    pub certs: Arc<ClientCerts>,
    /// version string returned from /version and passed to doprf_client to identify us
    pub synthclient_version: String,
    pub persistence_connection: Arc<Connection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreeningType {
    Normal,
    Demo,
}

impl SynthClientState {
    pub fn max_request_bp(&self, screening_type: ScreeningType) -> usize {
        match screening_type {
            ScreeningType::Demo => self.app_cfg.limited_max_request_bp,
            ScreeningType::Normal => self.app_cfg.default_max_request_bp,
        }
    }

    pub fn limit_config(&self, screening_type: ScreeningType) -> LimitConfiguration {
        LimitConfiguration {
            memory_limit: self.app_cfg.memorylimit,
            max_request_bp: self.max_request_bp(screening_type),
            limits: &self.limits,
        }
    }
}
