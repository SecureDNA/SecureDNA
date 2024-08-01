// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use clap::{crate_version, Args, Parser};
use hyper::StatusCode;
use serde::Deserialize;
use tracing::info;

use minhttp::mpserver::cli::ServerConfigSource;
use minhttp::mpserver::common::run_server;
use minhttp::mpserver::traits::RelativeConfig;
use minhttp::mpserver::MultiplaneServer;
use minhttp::response::text;

#[derive(Debug, Parser)]
#[clap(
    name = "mpserver",
    about = "Example Multiplane Server",
    version = crate_version!(),
)]
struct Opts {
    #[command(flatten)]
    config: ServerConfigSource<Config>,
}

#[derive(Clone, Debug, Args, Deserialize)]
#[allow(dead_code)]
struct Config {
    #[arg(long, default_value_t)]
    #[serde(default)]
    delay: u8,

    #[arg(long, default_value_t = default_times())]
    #[serde(default = "default_times")]
    times: u8,

    #[arg(long)]
    message: String,
}

impl RelativeConfig for Config {}

fn default_times() -> u8 {
    1
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let load_cfg = Opts::parse().config.into_load_cfg_fn();
    let builder = MultiplaneServer::builder()
        .with_reconfigure(|server_cfg, _prev_conf| async move {
            let app_cfg: Config = server_cfg.main.custom;
            info!("Loading new config: {app_cfg:?}");
            Ok::<_, std::convert::Infallible>(Arc::new(app_cfg))
        })
        .with_response(|state, _addr, _req| async move {
            tokio::time::sleep(std::time::Duration::from_secs(state.delay as u64)).await;
            let message: String = (0..state.times).map(|_| state.message.as_str()).collect();
            text(StatusCode::OK, message)
        });

    run_server(load_cfg, builder).await.unwrap();
}
