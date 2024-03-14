// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use hdb::shims::genhdb;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    //tracing_subscriber::fmt::init();

    let opts = genhdb::Opts::parse();
    genhdb::main(&opts)
}
