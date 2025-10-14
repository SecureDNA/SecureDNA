// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command-line tool to verify a verifiable screening request-response pair.

use std::fs;
use std::path::PathBuf;
use std::process::exit;

use anyhow::Context;
use clap::Parser;

use verify::fetch::NetworkHistoryFetcher;
use verify::verify;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Verifies a verifiable screening request-response pair.",
    long_about = None
)]
struct Args {
    /// Path to the JSON file containing the screening request.
    #[arg(value_name = "REQUEST_JSON_PATH")]
    request_json_path: PathBuf,

    /// Path to the JSON file containing the screening response.
    #[arg(value_name = "RESPONSE_JSON_PATH")]
    response_json_path: PathBuf,

    /// Grace period in seconds for token rotation checks during verification.
    /// When rotating from token 1 to token 2, token 1 will be considered valid
    /// for this many seconds after the last acknowledgement of token 2.
    #[arg(short = 'g', long, default_value_t = 24 * 3600, value_name = "SECONDS")]
    rotation_grace_period_seconds: i64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match run(args).await {
        Ok(()) => println!("Verification successful."),
        Err(e) => {
            eprintln!("Error: {e:?}");
            exit(1);
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    let req_path = args.request_json_path.display();
    let request_json = fs::read_to_string(&args.request_json_path)
        .with_context(|| format!("Failed to read request file '{req_path}'"))?;

    let res_path = args.response_json_path.display();
    let response_json = fs::read_to_string(&args.response_json_path)
        .with_context(|| format!("Failed to read response file '{res_path}'"))?;

    println!("Verifying response '{res_path}' against request '{req_path}'...",);

    verify(
        &request_json,
        &response_json,
        args.rotation_grace_period_seconds,
        &NetworkHistoryFetcher,
    )
    .await
    .context("Verification failed")
}
