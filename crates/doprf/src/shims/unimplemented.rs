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

pub fn main<Out: Write, Err: Write>(
    _opts: &Opts,
    _stdout: &mut Out,
    stderr: &mut Err,
) -> std::io::Result<()> {
    writeln!(
        stderr,
        "This tool is only available with the centralized_keygen feature enabled"
    )?;
    std::process::exit(1);
}
