// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use clap::{crate_version, ArgAction, Parser};

use doprf::active_security::Commitment;
use doprf::party::KeyserverId;
use doprf::prf::KeyShare;

#[derive(Debug, Parser)]
#[clap(
    name = "keyserver",
    about = "SecureDNA DOPRF Key Server",
    version = crate_version!()
)]
pub struct Opts {
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
        short,
        long,
        help = "Port to listen on.",
        default_value = "80",
        env = "SECUREDNA_KEYSERVER_PORT"
    )]
    pub port: u16,

    #[clap(
        short,
        long,
        help = "Port to listen on for monitoring plane.",
        env = "SECUREDNA_KEYSERVER_MONITORING_PLANE_PORT"
    )]
    pub monitoring_plane_port: Option<u16>,

    #[clap(
        long,
        help = "Maximum simultaneously connected clients before connections are no longer accepted",
        default_value = "1024",
        env = "SECUREDNA_KEYSERVER_MAX_CLIENTS"
    )]
    pub max_clients: usize,

    #[clap(
        long,
        help = "Maximum simultaneously connected monitoring plane clients before connections are no longer accepted",
        default_value = "1024",
        env = "SECUREDNA_KEYSERVER_MAX_MONITORING_PLANE_CLIENTS"
    )]
    pub max_monitoring_plane_clients: usize,

    #[clap(
        long,
        help = "Maximum simultaneous hashing/encryption requests before 503 unavailable is returned",
        default_value = "512",
        env = "SECUREDNA_KEYSERVER_MAX_HEAVY_CLIENTS"
    )]
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
        default_value = "100000"
    )]
    pub scep_json_size_limit: u64,

    #[clap(
        long,
        help = "Directory containing manufacturer root certs for SCEP client cert verification",
        env = "SECUREDNA_KEYSERVER_MANUFACTURER_ROOTS"
    )]
    pub manufacturer_roots: PathBuf,

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
    pub allow_insecure_cookie: bool,
}
