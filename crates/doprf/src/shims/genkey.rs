// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::io::Write;

#[derive(Debug, Parser)]
#[clap(
    name = "genkey",
    about = "Generates a secret key for a SecureDNA DOPRF"
)]
pub struct Opts {}

pub fn main<Out: Write, Err: Write>(
    _opts: &Opts,
    stdout: &mut Out,
    _stderr: &mut Err,
) -> std::io::Result<()> {
    let key = Scalar::random(&mut OsRng);
    writeln!(stdout, "{}", hex::encode(key.to_bytes()))
}
