// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use certificate_client::common::cli_default_directory;
use clap::Parser;
use std::io::stderr;
use std::io::stdout;
use std::io::Write;

use certificate_client::shims::create_token;

fn main() -> Result<(), std::io::Error> {
    let opts = create_token::CreateTokenOpts::parse();
    let default_directory = match cli_default_directory() {
        Ok(dir) => dir,
        Err(err) => {
            writeln!(&mut stderr(), "{err}")?;
            return Ok(());
        }
    };

    #[cfg(not(feature = "env_passphrase"))]
    let passphrase_reader = certificate_client::passphrase_reader::PromptNewPassphraseReader::new(
        certificate_client::passphrase_reader::CREATE_TOKEN_PASSPHRASE_PROMPT,
    );

    #[cfg(feature = "env_passphrase")]
    let passphrase_reader = certificate_client::passphrase_reader::EnvVarPassphraseReader;

    create_token::main(
        &opts,
        passphrase_reader,
        &default_directory,
        &mut stdout(),
        &mut stderr(),
    )
}
