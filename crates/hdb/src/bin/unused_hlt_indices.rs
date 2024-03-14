// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use clap::{crate_version, Parser};

use hdb::shims::unused_hlt_indices;

#[derive(Debug, Parser)]
#[clap(
    name = "unused_hlt_indices",
    about = "Scans an HDB directory to see which HLT indices are not being used.",
    version = crate_version!()
)]
pub struct Opts {
    #[clap(help = "location of the database (as a directory)")]
    hdb_dir: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    unused_hlt_indices::scan(&opts.hdb_dir)
}
