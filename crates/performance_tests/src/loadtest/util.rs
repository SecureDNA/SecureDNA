// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs;
use std::path::Path;

/* Utility functions */

pub fn create_results_dir(timestamp: u64) {
    let path = Path::new("results").join(timestamp.to_string());
    println!("Creating results dir: {} ", path.as_path().display());
    fs::create_dir_all(path).unwrap();
}
