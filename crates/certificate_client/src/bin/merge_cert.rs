// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Write;
use std::io::{stderr, stdout};

use certificate_client::default_filepath::cli_default_directory;
use clap::Parser;

use certificate_client::shims::merge_cert;

fn main() -> Result<(), std::io::Error> {
    let opts = merge_cert::MergeCertOpts::parse();
    let default_directory = match cli_default_directory() {
        Ok(dir) => dir,
        Err(err) => {
            writeln!(&mut stderr(), "{err}")?;
            return Ok(());
        }
    };

    merge_cert::main(&opts, &default_directory, &mut stdout(), &mut stderr())
}
