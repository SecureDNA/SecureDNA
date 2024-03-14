// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{ErrorKind, Write};
use std::num::NonZeroU32;

use clap::{ArgAction, Parser};

use crate::active_security::commitments_from_secret_and_keyshares;
use crate::prf::KeyShare;

#[derive(Debug, Parser)]
#[clap(
    name = "genactivesecuritykey",
    about = "Generates commitments from the master secret key and keyshares for use in active security"
)]
pub struct Opts {
    #[clap(help = "The randomly generated secret key")]
    pub secret_key: KeyShare,

    #[clap(long, action = ArgAction::Set,
        value_delimiter = ',',
        help = "The keyshares corresponding to indices 1 to Q, where Q is the number of keyholders required")]
    pub keyshares: Vec<KeyShare>,

    #[clap(
        long,
        short,
        help = "The number of keyholders required to reach quorum"
    )]
    pub keyholders_required: NonZeroU32,
}

pub fn main<Out: Write, Err: Write>(
    opts: &Opts,
    stdout: &mut Out,
    _stderr: &mut Err,
) -> std::io::Result<()> {
    let commitments = commitments_from_secret_and_keyshares(
        &opts.secret_key,
        &opts.keyshares,
        opts.keyholders_required,
    )
    .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;

    for tc in commitments.iter() {
        writeln!(stdout, "{}", tc)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU32,
        str::{from_utf8, FromStr},
    };

    use curve25519_dalek::Scalar;
    use rand::{thread_rng, Rng};

    use crate::{
        active_security::Commitment, prf::generate_keyshares, shims::genactivesecuritykey,
    };

    #[test]
    fn can_generate_commitments_from_secret_and_keyshares() {
        let mut rng = thread_rng();
        let secret_key = Scalar::random(&mut rng).into();

        let keyholders_required = rng.gen_range(1..=10);
        let num_keyholders = rng.gen_range(keyholders_required..=keyholders_required + 5);

        let keyshares = generate_keyshares(
            &secret_key,
            NonZeroU32::new(keyholders_required).unwrap(),
            NonZeroU32::new(num_keyholders).unwrap(),
            &mut rng,
        )
        .unwrap();

        let opts = genactivesecuritykey::Opts {
            secret_key,
            keyshares,
            keyholders_required: NonZeroU32::new(keyholders_required).unwrap(),
        };
        let mut stdout: Vec<u8> = vec![];
        let mut stderr: Vec<u8> = vec![];

        let result = genactivesecuritykey::main(&opts, &mut stdout, &mut stderr);
        assert!(result.is_ok());

        let commitments = from_utf8(&stdout)
            .unwrap()
            .lines()
            .map(|l| Commitment::from_str(l).expect("Got invalid commitment"))
            .collect::<Vec<_>>();

        // check that we get expected commitment count
        assert_eq!(commitments.len(), keyholders_required as usize);
    }
}
