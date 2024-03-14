// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use std::io::stderr;
use std::io::stdout;

use certificate_client::shims::inspect_token;

fn main() -> Result<(), std::io::Error> {
    let opts = inspect_token::InspectTokenOpts::parse();
    inspect_token::main(&opts, &mut stdout(), &mut stderr())
}
