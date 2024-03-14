// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;

use hdb::shims::genindex;

fn main() -> anyhow::Result<()> {
    let opts = genindex::Opts::parse();
    genindex::main(&opts)
}
