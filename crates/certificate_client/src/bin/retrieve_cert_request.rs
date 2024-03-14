// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use std::io::stderr;
use std::io::stdout;

use certificate_client::shims::retrieve_cert_request;

fn main() -> Result<(), std::io::Error> {
    let opts = retrieve_cert_request::RetrieveRequestOpts::parse();
    retrieve_cert_request::main(&opts, &mut stdout(), &mut stderr())
}
