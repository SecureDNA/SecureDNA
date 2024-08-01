// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;

use minhttp::mpserver::common::run_server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = keyserver::Opts::parse();
    let load_cfg_fn = opts.config.into_load_cfg_fn();
    run_server(load_cfg_fn, keyserver::server_setup()).await
}
