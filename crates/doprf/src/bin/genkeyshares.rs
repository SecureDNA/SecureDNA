// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use doprf::shims::genkeyshares;

fn main() -> std::io::Result<()> {
    let opts = genkeyshares::Opts::parse();
    genkeyshares::main(&opts, &mut std::io::stdout(), &mut std::io::stderr())
}
