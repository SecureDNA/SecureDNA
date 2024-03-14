// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use std::io::Write;

#[derive(Debug, Parser)]
#[clap(
    name = "unimplemented",
    about = "This tool is not implemented without the `centralized_keygen` feature."
)]
pub struct Opts {}

pub fn main(_opts: &Opts) -> anyhow::Result<()> {
    writeln!(
        std::io::stderr(),
        "This tool is only available with the centralized_keygen feature enabled"
    )?;
    std::process::exit(1);
}
