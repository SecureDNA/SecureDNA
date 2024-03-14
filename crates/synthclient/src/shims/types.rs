// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{crate_version, ArgAction, Args, CommandFactory, Parser};
use tokio::sync::Mutex;
use url::Url;

use crate::api::Region;
use crate::parsefasta::{CheckerConfiguration, CurrentSystemLoadTracker, LimitConfiguration};
use crate::rate_limiter::{RateLimiter, SystemTimeHourProvider};
use doprf_client::server_selection::{ServerEnumerationSource, ServerSelector};
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
    // WARNING: keyservers use num_args (multi-argument)
    // and hence it is discouraged to use positional arguments
    // https://docs.rs/clap/latest/clap/struct.Arg.html#method.num_args
    #[clap(
        short,
        long,
        help = "Port to listen on.",
        default_value = "80",
        env = "SECUREDNA_SYNTHCLIENT_PORT"
    )]
    pub port: u16,

    #[command(flatten)]
    pub enumeration: EnumerationArgs,

    #[command(flatten)]
    pub selection_refresh: SelectionRefreshArgs,

    #[command(flatten)]
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
        default_value = "1000000"
    )]
    pub default_max_request_bp: usize,

    #[clap(
        long,
        help = "In a public demo setting, screening requests are limited to this many base pairs.",
        env = "SECUREDNA_SYNTHCLIENT_LIMITED_MAX_REQUEST_BP",
        default_value = "10000"
    )]
    pub limited_max_request_bp: usize,

    #[clap(
        long,
        help = "Disable Prometheus statistics",
        env = "SECUREDNA_SYNTHCLIENT_DISABLE_STATISTICS"
    )]
    pub disable_statistics: bool,

    #[clap(
        long,
        help = "Secret key for validating reCAPTCHA v3 responses (enables a demo on https://securedna.org/)",
        env = "SECUREDNA_SYNTHCLIENT_RECAPTCHA_SECRET_KEY"
    )]
    pub recaptcha_secret_key: Option<String>,

    #[clap(
        long,
        help = "Hourly rate limit on reCAPTCHA screening requests from the same IP address",
        default_value = "5",
        env = "SECUREDNA_SYNTHCLIENT_RECAPTCHA_REQUESTS_PER_HOUR"
    )]
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
        default_value = "https://pages.securedna.org/demo/"
    )]
    pub frontend_url: Url,

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
        env = "SECUREDNA_SYNTHCLIENT_MAX_CLIENTS"
    )]
    pub max_clients: usize,

    #[clap(
        long,
        help = "Maximum simultaneously connected monitoring plane clients before connections are no longer accepted",
        default_value = "1024",
        env = "SECUREDNA_SYNTHCLIENT_MAX_MONITORING_PLANE_CLIENTS"
    )]
    pub max_monitoring_plane_clients: usize,

    #[clap(
        long,
        help = "Maximum size of JSON request bodies",
        default_value = "100000",
        env = "SECUREDNA_SYNTHCLIENT_JSON_SIZE_LIMIT"
    )]
    pub json_size_limit: u64,
}

#[derive(Args, Debug)]
pub struct EnumerationArgs {
    #[clap(
        long,
        help = "Server tier to use for enumeration.",
        default_value_t = Tier::Prod,
        env = "SECUREDNA_SYNTHCLIENT_ENUMERATE_TIER",
    )]
    pub enumerate_tier: Tier,

    #[clap(
        long,
        help = "Apex domain to use for enumeration.",
        default_value = "securedna.org",
        env = "SECUREDNA_SYNTHCLIENT_ENUMERATE_APEX"
    )]
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
                tier: self.enumerate_tier,
                apex: self.enumerate_apex.clone(),
            }
        } else {
            ServerEnumerationSource::NativeDns {
                tier: self.enumerate_tier,
                apex: self.enumerate_apex.clone(),
            }
        }
    }
}

#[derive(Args, Debug)]
pub struct SelectionRefreshArgs {
    #[clap(
        long,
        action = ArgAction::Set,
        default_value = "1day",
        help = "Timeout before a cached selection will be refreshed in the background. Uses formatting from the `humantime` crate.",
        env = "SECUREDNA_SYNTHCLIENT_SOFT_TIMEOUT",
    )]
    pub soft_timeout: humantime::Duration,
    #[clap(
        long,
        action = ArgAction::Set,
        default_value = "1week",
        help = "Timeout before a cached selection will be refreshed in the _foreground_, making all requests wait. Uses formatting from the `humantime` crate.",
        env = "SECUREDNA_SYNTHCLIENT_BLOCKING_TIMEOUT",
    )]
    pub blocking_timeout: humantime::Duration,
    #[clap(
        long,
        action = ArgAction::Set,
        default_value = "1",
        help = "If nonzero, an extra amount of good keyservers, on top of the quorum threshold, below which the selection will be refreshed in the background.",
        env = "SECUREDNA_SYNTHCLIENT_SOFT_EXTRA_KS",
    )]
    pub soft_extra_keyserver_threshold: u32,
    #[clap(
        long,
        action = ArgAction::Set,
        default_value = "1",
        help = "If nonzero, an extra amount of good hdbs, on top of the one needed for quorum, below which the selection will be refreshed in the background.",
        env = "SECUREDNA_SYNTHCLIENT_SOFT_EXTRA_HDB",
    )]
    pub soft_extra_hdb_threshold: u32,
}

#[derive(Args, Debug)]
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
    pub fn validate_and_build(&self) -> ClientCerts {
        let result = (|| {
            let passphrase = std::fs::read_to_string(&self.keypair_passphrase_file)
                .context("reading keypair passphrase file")?;
            let passphrase = passphrase.trim();

            if self.use_test_roots_do_not_use_this_in_prod {
                ClientCerts::load_with_test_roots(&self.token_file, &self.keypair_file, passphrase)
            } else {
                ClientCerts::load_with_prod_roots(&self.token_file, &self.keypair_file, passphrase)
            }
        })();

        match result {
            Ok(v) => v,
            Err(e) => {
                let mut cmd = Opts::command();
                cmd.error(clap::error::ErrorKind::Io, e).exit();
            }
        }
    }
}

pub struct SynthClientState {
    pub opts: Opts,
    pub server_selector: Arc<ServerSelector>,
    pub metrics: Option<Arc<SynthClientMetrics>>,
    pub limits: CurrentSystemLoadTracker,
    pub demo_rate_limiter: Mutex<RateLimiter<IpAddr, SystemTimeHourProvider>>,
    pub certs: Arc<ClientCerts>,
    /// version string returned from /version and passed to doprf_client to identify us
    pub synthclient_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreeningType {
    Normal,
    Demo,
}

impl SynthClientState {
    pub fn make_config(
        &self,
        screening_type: ScreeningType,
        region: Region,
        include_debug_info: bool,
        use_http: bool,
        certs: Arc<ClientCerts>,
        provider_reference: Option<String>,
    ) -> CheckerConfiguration {
        let max_request_bp = match screening_type {
            ScreeningType::Demo => self.opts.limited_max_request_bp,
            ScreeningType::Normal => self.opts.default_max_request_bp,
        };

        let limit_config = LimitConfiguration {
            memory_limit: self.opts.memorylimit,
            max_request_bp,
            limits: &self.limits,
        };

        CheckerConfiguration {
            server_selector: self.server_selector.clone(),
            certs,
            include_debug_info,
            metrics: self.metrics.clone(),
            region,
            limit_config,
            use_http,
            provider_reference,
            synthclient_version_hint: &self.synthclient_version,
        }
    }
}
