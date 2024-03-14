// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::stderr;
use std::io::stdout;
use std::io::Write;

use certificate_client::common::cli_default_directory;
use certificate_client::shims::create_key;
use clap::Parser;

fn main() -> Result<(), std::io::Error> {
    let opts = create_key::CreateKeyOpts::parse();

    #[cfg(not(feature = "env_passphrase"))]
    let passphrase_reader = certificate_client::passphrase_reader::PromptNewPassphraseReader::new(
        certificate_client::passphrase_reader::CREATE_KEY_PASSPHRASE_PROMPT,
    );

    #[cfg(feature = "env_passphrase")]
    let passphrase_reader = certificate_client::passphrase_reader::EnvVarPassphraseReader;

    let default_directory = match cli_default_directory() {
        Ok(dir) => dir,
        Err(err) => {
            writeln!(&mut stderr(), "{err}")?;
            return Ok(());
        }
    };
    create_key::main(
        &opts,
        passphrase_reader,
        &default_directory,
        &mut stdout(),
        &mut stderr(),
    )
}
