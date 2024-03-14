// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Write;
use std::io::{stderr, stdout};

use certificate_client::common::cli_default_directory;
use clap::Parser;

use certificate_client::shims::sign_cert;

fn main() -> Result<(), std::io::Error> {
    let opts = sign_cert::SignCertOpts::parse();
    let default_directory = match cli_default_directory() {
        Ok(dir) => dir,
        Err(err) => {
            writeln!(&mut stderr(), "{err}")?;
            return Ok(());
        }
    };

    #[cfg(not(feature = "env_passphrase"))]
    let passphrase_reader =
        certificate_client::passphrase_reader::PromptExistingPassphraseReader::new(
            certificate_client::passphrase_reader::ENTER_PASSPHRASE_PROMPT,
        );

    #[cfg(feature = "env_passphrase")]
    let passphrase_reader = certificate_client::passphrase_reader::EnvVarPassphraseReader;

    sign_cert::main(
        &opts,
        passphrase_reader,
        &default_directory,
        &mut stdout(),
        &mut stderr(),
    )
}
