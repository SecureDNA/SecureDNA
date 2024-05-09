// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result};
use clap::{ArgAction, CommandFactory, FromArgMatches, Parser};
use scep::{error::ClientPrevalidation, states::OpenedClientState};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use certificates::{key_traits::CanLoadKey, DatabaseTokenGroup, KeyserverTokenGroup, TokenGroup};
use doprf::{
    party::KeyserverId,
    prf::{CompletedHashValue, Query},
    tagged::{HashTag, TaggedHash},
};
use http_client::{BaseApiClient, HttpError, HttpsToHttpRewriter};
use packed_ristretto::PackedRistrettos;
use scep_client_helpers::{ClientCerts, ScepClient};
use securedna_versioning::version::get_version;
use shared_types::{
    hdb::HdbScreeningResult,
    requests::RequestId,
    server_selection::{
        HdbQualificationResponse, KeyserverQualificationResponse, QualificationRequest, Tier,
    },
    synthesis_permission::Region,
};

#[derive(Debug, Parser)]
#[command(
    version,
    author,
    about = "A tool for making requests against SecureDNA internal servers.",
    long_about = "scurl (/skɜːrl/) is a command-line utility that allows you to make requests against SecureDNA internal servers using the SSP and (optionally) SCEP protocols. You can specify one or more server URLs manually, or use DNS enumeration."
)]
struct Arguments {
    #[arg(
        short,
        long,
        help = "Suppress non-error output and set the log level to WARN."
    )]
    quiet: bool,

    #[arg(
        short,
        long,
        action = ArgAction::Count,
        help = "Increase verbosity level, can be used multiple times."
    )]
    verbose: u8,

    #[arg(
        short,
        long,
        value_name = "DOMAIN",
        action = ArgAction::Append,
        help = "Specify a keyserver domain to send requests to."
    )]
    keyserver: Vec<String>,

    #[arg(
        short = 'd',
        long,
        value_name = "DOMAIN",
        action = ArgAction::Append,
        help = "Specify an hdbserver domain to send requests to."
    )]
    hdbserver: Vec<String>,

    #[arg(
        long,
        short,
        value_name = "TIER",
        help = "Use DNS enumeration instead of specifying servers, e.g. 'prod'.",
        conflicts_with = "keyserver",
        conflicts_with = "hdbserver"
    )]
    enumerate: Option<Tier>,

    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Only run SSP, don't run SCEP. Certificates aren't required in this mode."
    )]
    ssp_only: bool,

    #[arg(
        long,
        short,
        default_value = None,
        help = "Path to .st token for SCEP. Requires -c / --keypair-path and -p / --passphrase-path.",
        requires = "keypair_path",
        requires = "passphrase_path",
    )]
    token_path: Option<PathBuf>,

    #[arg(
        long,
        short = 'c',
        default_value = None,
        help = "Path to .priv keypair for SCEP. Requires -t / --token-path and -p / --passphrase-path.",
        requires = "token_path",
        requires = "passphrase_path",
    )]
    keypair_path: Option<PathBuf>,

    #[arg(
        long,
        short,
        default_value = None,
        help = "Path to passphrase file for SCEP. Requires -t / --token-path and -c / --keypair-path.",
        requires = "token_path",
        requires = "keypair_path",
    )]
    passphrase_path: Option<PathBuf>,

    #[arg(
        long,
        short = 'z',
        action = ArgAction::SetTrue,
        help = "Use compact (one-line) format for output."
    )]
    compact: bool,

    #[arg(
        long,
        short,
        action = ArgAction::SetTrue,
        help = "Use the test certificate hierarchy for SCEP, instead of the default production hierarchy.",
    )]
    use_test_roots: bool,

    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Run requests over http:// instead of https://"
    )]
    use_http: bool,

    #[arg(
        long,
        value_name="PROVIDER_ADDR",
        default_value = None,
        help = "Use a DNS-over-HTTPS provider, such as `1.1.1.1`, for `--enumerate`."
    )]
    dns_over_https: Option<String>,

    #[arg(
        long,
        default_value = "securedna.org",
        help = "Apex domain to use for `--enumerate`."
    )]
    enumeration_apex: String,
}

impl Arguments {
    async fn build_config(&self) -> anyhow::Result<Config> {
        let (keyservers, hdbservers) = if let Some(tier) = &self.enumerate {
            if let Some(provider) = &self.dns_over_https {
                doprf_client::server_selection::enumerate(
                    &doprf_client::server_selection::dns::DnsOverHttps::new(provider),
                    tier,
                    &self.enumeration_apex,
                )
                .await
            } else {
                doprf_client::server_selection::enumerate(
                    doprf_client::server_selection::dns::NativeDns,
                    tier,
                    &self.enumeration_apex,
                )
                .await
            }
        } else {
            (self.keyserver.clone(), self.hdbserver.clone())
        };
        let keyservers = keyservers.into_iter().map(ServerDomain::Keyserver);
        let hdbservers = hdbservers.into_iter().map(ServerDomain::Hdbserver);
        let servers = keyservers.chain(hdbservers).collect();

        let run_scep = !self.ssp_only;

        let client_certs = match (
            run_scep,
            &self.token_path,
            &self.keypair_path,
            &self.passphrase_path,
        ) {
            (true, Some(token_path), Some(keypair_path), Some(passphrase_path)) => {
                let passphrase = std::fs::read_to_string(passphrase_path)
                    .with_context(|| format!("reading passphrase from {passphrase_path:?}"))?;
                let passphrase = passphrase.trim();

                Some(Arc::new(
                    if self.use_test_roots {
                        ClientCerts::load_with_test_roots(token_path, keypair_path, passphrase)
                    } else {
                        ClientCerts::load_with_prod_roots(token_path, keypair_path, passphrase)
                    }
                    .context("loading certificates")?,
                ))
            }
            _ => None,
        };

        if run_scep && client_certs.is_none() {
            anyhow::bail!("--token-path, --keypair-path, and --passphrase-path are required when using scurl for SCEP.");
        }

        Ok(Config {
            servers,
            request_config: RequestConfig {
                run_scep: client_certs,
                use_http: self.use_http,
                fmt: OutputFormat {
                    quiet: self.quiet,
                    compact: self.compact,
                },
            },
        })
    }
}

#[derive(Clone)]
struct Config {
    servers: Vec<ServerDomain>,
    request_config: RequestConfig,
}

#[derive(Clone)]
struct RequestConfig {
    /// if Some, run SCEP with these certs. if None, don't run SCEP.
    run_scep: Option<Arc<ClientCerts>>,
    use_http: bool,
    fmt: OutputFormat,
}

#[derive(Debug, Clone, Copy)]
struct OutputFormat {
    quiet: bool,
    compact: bool,
}

impl OutputFormat {
    fn output_str(&self, operation: &str, domain: &str, object: &str) {
        if self.quiet {
            return;
        }
        if self.compact {
            println!("{operation} domain={domain}: {object}");
        } else {
            println!("{operation} domain={domain}:\n{object}\n");
        }
    }

    fn output(&self, operation: &str, domain: &str, object: &impl Serialize) {
        if self.quiet {
            return;
        }
        self.output_str(operation, domain, &self.json_to_string(object))
    }

    fn json_to_string(&self, object: &impl Serialize) -> String {
        if self.compact {
            serde_json::to_string(object).unwrap()
        } else {
            serde_json::to_string_pretty(object).unwrap()
        }
    }
}

#[derive(Debug, Clone)]
enum ServerDomain {
    Keyserver(String),
    Hdbserver(String),
}

impl fmt::Display for ServerDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerDomain::Keyserver(d) => write!(f, "keyserver {d}"),
            ServerDomain::Hdbserver(d) => write!(f, "hdbserver {d}"),
        }
    }
}

#[tokio::main]
async fn main() -> ! {
    let cmd = Arguments::command();
    let after_help = format!(
        "{}Examples:{}
# run a full cycle of requests against a single keyserver
scurl -t token.st -c token.priv -p token.passphrase \\
    -k 1.ks.prod.securedna.org

# run a full cycle of requests against a full set of servers
scurl -t token.st -c token.priv -p token.passphrase \\
    -d 1.db.prod.securedna.org -k={{1,2,3,4,5}}.ks.prod.securedna.org

# run SSP against all servers in prod, with compact output
scurl --ssp-only --enumerate prod -z
",
        cmd.get_styles().get_header().render(),
        cmd.get_styles().get_header().render_reset()
    );
    let mut cmd = cmd.after_help(after_help);
    cmd.build();

    let mut matches = cmd.get_matches();
    let args = match Arguments::from_arg_matches_mut(&mut matches) {
        Ok(args) => args,
        Err(e) => {
            let e = e.format(&mut Arguments::command());
            e.exit();
        }
    };

    let subscriber = FmtSubscriber::builder()
        .with_writer(std::io::stderr)
        .with_max_level(match (args.quiet, args.verbose) {
            (true, _) => Level::WARN,
            (false, 0) => Level::INFO,
            (false, 1) => Level::DEBUG,
            (false, _) => Level::TRACE,
        })
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let config = match args.build_config().await {
        Ok(config) => config,
        Err(err) => {
            error!("{err:#}");
            std::process::exit(2);
        }
    };

    if let Err(err) = scurl(&config).await {
        error!("{err:#}");
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}

async fn scurl(config: &Config) -> Result<()> {
    let mut had_error = false;

    for server in &config.servers {
        let result = match server {
            ServerDomain::Keyserver(domain) => {
                scurl_one::<KeyserverScurlable>(domain, &config.request_config).await
            }
            ServerDomain::Hdbserver(domain) => {
                scurl_one::<HdbserverScurlable>(domain, &config.request_config).await
            }
        };
        if let Err(err) = result {
            error!("scurl failed for {server}: {err:#}");
            had_error = true;
        }
    }

    if had_error {
        anyhow::bail!("Not all requests completed successfully.")
    } else {
        Ok(())
    }
}

async fn scurl_one<S>(domain: &str, request_config: &RequestConfig) -> Result<()>
where
    S: Scurlable,
    <S::TokenGroup as TokenGroup>::Token: CanLoadKey + std::fmt::Debug,
    S::QualificationResponse: serde::Serialize + serde::de::DeserializeOwned,
{
    let client = make_http_client(make_request_id(), request_config.use_http);

    ////////////////////////////////////////
    // qualification
    ////////////////////////////////////////

    let url = format!("https://{domain}/qualification");

    let request = QualificationRequest { client_version: 0 };
    let response = client
        .json_json_post::<_, serde_json::Value>(&url, &request)
        .await
        .with_context(|| format!("posting {url}"))?;

    let qualification =
        deserialize_or_pretty_error::<S::QualificationResponse>(request_config.fmt, response)?;

    request_config
        .fmt
        .output("ssp::qualify", domain, &qualification);

    ////////////////////////////////////////
    // scep (if enabled)
    ////////////////////////////////////////

    let certs = match request_config.run_scep.as_ref() {
        Some(client_certs) => client_certs.clone(),
        None => return Ok(()),
    };

    let client = ScepClient::new(
        client,
        format!("https://{domain}"),
        certs,
        scurl_version_hint(),
    );
    let (client, snoop) = ClientSnooper::new(client);

    let opened = S::open(&client, qualification).await.map_err(|err| {
        if let Some(open) = snoop.open_response() {
            anyhow::anyhow!("{err}: {}", request_config.fmt.json_to_string(open))
        } else {
            anyhow::anyhow!("{err}")
        }
    })?;

    request_config
        .fmt
        .output("scep::open", domain, snoop.open_response().unwrap());

    S::authenticate(&client, opened).await.map_err(|err| {
        if let Some(auth) = snoop.auth_response() {
            anyhow::anyhow!("{err}: {}", request_config.fmt.json_to_string(auth))
        } else {
            anyhow::anyhow!("{err}")
        }
    })?;

    request_config
        .fmt
        .output("scep::authenticate", domain, snoop.auth_response().unwrap());

    let out = S::scep_operation(&client).await?;
    request_config
        .fmt
        .output(&format!("scep::{}", S::OPERATION_NAME), domain, &out);

    Ok(())
}

/// Helper trait for handling per-server SSP/SCEP types
trait Scurlable {
    type QualificationResponse;
    type TokenGroup: TokenGroup + std::fmt::Debug;
    type ScepOperationOutput: serde::Serialize;
    const OPERATION_NAME: &'static str;

    async fn open(
        client: &ScepClient<Self::TokenGroup>,
        qualification: Self::QualificationResponse,
    ) -> Result<OpenedClientState, scep_client_helpers::Error<ClientPrevalidation>>;

    async fn authenticate(
        client: &ScepClient<Self::TokenGroup>,
        opened_state: OpenedClientState,
    ) -> Result<(), scep_client_helpers::Error<ClientPrevalidation>>;

    async fn scep_operation(
        client: &ScepClient<Self::TokenGroup>,
    ) -> Result<Self::ScepOperationOutput, HttpError>;
}

struct KeyserverScurlable;

impl Scurlable for KeyserverScurlable {
    type QualificationResponse = KeyserverQualificationResponse;
    type TokenGroup = KeyserverTokenGroup;
    type ScepOperationOutput = String;
    const OPERATION_NAME: &'static str = "keyserve";

    async fn open(
        client: &ScepClient<KeyserverTokenGroup>,
        qualification: KeyserverQualificationResponse,
    ) -> Result<OpenedClientState, scep_client_helpers::Error<ClientPrevalidation>> {
        let id = qualification.id;
        client.open(1, None, vec![id].into(), id).await
    }

    async fn authenticate(
        client: &ScepClient<KeyserverTokenGroup>,
        opened_state: OpenedClientState,
    ) -> Result<(), scep_client_helpers::Error<ClientPrevalidation>> {
        client.authenticate(opened_state, 1).await
    }

    async fn scep_operation(
        client: &ScepClient<KeyserverTokenGroup>,
    ) -> Result<Self::ScepOperationOutput, HttpError> {
        let resp = client
            .keyserve(&PackedRistrettos::new(vec![
                Query::hash_from_bytes_for_tests_only(&[1]).into(),
            ]))
            .await?;
        Ok(hex::encode(resp.encoded_items()[0]))
    }
}

struct HdbserverScurlable;

impl Scurlable for HdbserverScurlable {
    type QualificationResponse = HdbQualificationResponse;
    type TokenGroup = DatabaseTokenGroup;
    type ScepOperationOutput = HdbScreeningResult;
    const OPERATION_NAME: &'static str = "screen";

    async fn open(
        client: &ScepClient<DatabaseTokenGroup>,
        _: HdbQualificationResponse,
    ) -> Result<OpenedClientState, scep_client_helpers::Error<ClientPrevalidation>> {
        client
            .open(
                1,
                None,
                vec![KeyserverId::try_from(1).unwrap()].into(),
                Region::All,
                false,
            )
            .await
    }

    async fn authenticate(
        client: &ScepClient<DatabaseTokenGroup>,
        opened_state: OpenedClientState,
    ) -> Result<(), scep_client_helpers::Error<ClientPrevalidation>> {
        client.authenticate(opened_state, 1).await
    }

    async fn scep_operation(
        client: &ScepClient<DatabaseTokenGroup>,
    ) -> Result<Self::ScepOperationOutput, HttpError> {
        client
            .screen(&PackedRistrettos::new(vec![TaggedHash {
                tag: HashTag::new(true, 0, 0),
                hash: CompletedHashValue::hash_from_bytes_for_tests_only(&[1]),
            }
            .into()]))
            .await
    }
}

/// Helper for snooping on `ScepClient` responses--see `ScepClient::snoop`
struct ClientSnooper {
    open_response: Arc<OnceLock<serde_json::Value>>,
    auth_response: Arc<OnceLock<serde_json::Value>>,
}

impl ClientSnooper {
    fn new<T>(client: ScepClient<T>) -> (ScepClient<T>, Self)
    where
        T: TokenGroup + std::fmt::Debug,
        T::Token: CanLoadKey + std::fmt::Debug,
        T::AssociatedRole: std::fmt::Debug,
    {
        let open_response: Arc<OnceLock<serde_json::Value>> = Arc::new(OnceLock::new());
        let auth_response: Arc<OnceLock<serde_json::Value>> = Arc::new(OnceLock::new());
        let client = client.snoop(
            {
                let snooped_open_response = open_response.clone();
                Box::new(move |value| {
                    snooped_open_response
                        .set(value.clone())
                        .expect("should not be set twice");
                })
            },
            {
                let snooped_auth_response = auth_response.clone();
                Box::new(move |value| {
                    snooped_auth_response
                        .set(value.clone())
                        .expect("should not be set twice");
                })
            },
        );
        (
            client,
            Self {
                open_response,
                auth_response,
            },
        )
    }

    fn open_response(&self) -> Option<&serde_json::Value> {
        self.open_response.get()
    }

    fn auth_response(&self) -> Option<&serde_json::Value> {
        self.auth_response.get()
    }
}

/// Make scurl version hint string `scurl-{git_version}`
fn scurl_version_hint() -> String {
    format!("scurl-{}", get_version())
}

/// Makes a new prefixed `RequestId``
fn make_request_id() -> RequestId {
    RequestId::new_unique_with_prefix("scurl")
}

/// Builds a new BaseApiClient, using `HttpsToHttpRewriter` if `use_http` is `true`.
fn make_http_client(request_id: RequestId, use_http: bool) -> BaseApiClient {
    let api_client = BaseApiClient::new(request_id);
    if use_http {
        HttpsToHttpRewriter::inject(api_client)
    } else {
        api_client
    }
}

fn deserialize_or_pretty_error<T: DeserializeOwned + Serialize>(
    fmt: OutputFormat,
    value: serde_json::Value,
) -> anyhow::Result<T> {
    serde_json::from_value::<T>(value.clone()).map_err(|err| {
        anyhow::anyhow!(
            "invalid {typename}: {err}: {ser}",
            typename = std::any::type_name::<T>(),
            ser = fmt.json_to_string(&value),
        )
    })
}
