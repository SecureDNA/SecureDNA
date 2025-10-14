// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::stderr;
use std::io::stdout;
use std::io::Write;

use certificate_client::default_filepath::cli_default_directory;
use certificate_client::shims::audit;
use clap::Parser;

fn main() -> Result<(), std::io::Error> {
    let opts = audit::AuditOpts::parse();

    let default_directory = match cli_default_directory() {
        Ok(dir) => dir,
        Err(err) => {
            writeln!(&mut stderr(), "{err}")?;
            return Ok(());
        }
    };
    audit::main(&opts, &default_directory, &mut stdout(), &mut stderr())
}
