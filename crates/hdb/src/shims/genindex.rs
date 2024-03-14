// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::{crate_version, Parser};

use crate::database::Database;

#[derive(Debug, Parser)]
#[clap(
    name = "genindexes",
    about = "Regenerates index for SecureDNA hashed database",
    version = crate_version!()
)]
pub struct Opts {
    #[clap(help = "path to database (as a directory)")]
    pub database: PathBuf,

    #[clap(
        short,
        long,
        help = "Space used for database indexes, in megabytes",
        long_help = "\
Space used for database indexes, in megabytes

Ballpark attributes of various sized indexes:

  Size    Speedup           Index Build Time            Index Load Time
                     Local NVMe    Cloud SSD    Local NVMe    Cloud SSD
   1mb        22%          0.1s           5s            0s           0s
   4mb        28%          0.4s          20s            0s           0s
  16mb        35%          1.6s          80s            0s         0.1s
  64mb        45%            6s           6m          0.1s         0.5s
 256mb        50%           24s          22m          0.5s           2s
1024mb        55%           96s          88m            2s           8s

Note: Local NVMe = 250K IOPS; Cloud SSD = 6K IOPS\
        ",
        default_value = "1024"
    )]
    pub index_mb: u16,
}

pub fn main(opts: &Opts) -> anyhow::Result<()> {
    let index_bytes = opts.index_mb as usize * 1024 * 1024;
    Database::rebuild_index(&opts.database, index_bytes).context("failed to re-index database")?;
    Ok(())
}
