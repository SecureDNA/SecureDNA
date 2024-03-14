// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::ErrorKind;
use std::io::Write;
use std::num::NonZeroU32;

use clap::Parser;
use rand::rngs::OsRng;

use crate::prf::{generate_keyshares, KeyShare};

#[derive(Debug, Parser)]
#[clap(
    name = "genkeyshares",
    about = "Generates keyshares for a SecureDNA DOPRF"
)]
pub struct Opts {
    #[clap(help = "The randomly generated secret key to use to generate")]
    pub secret_key: KeyShare,

    #[clap(
        long,
        short,
        help = "The number of keyholders required to hash a value"
    )]
    pub keyholders_required: NonZeroU32,

    #[clap(long, short, help = "The total number of keyholders")]
    pub num_keyholders: NonZeroU32,
}

pub fn main<Out: Write, Err: Write>(
    opts: &Opts,
    stdout: &mut Out,
    _stderr: &mut Err,
) -> std::io::Result<()> {
    let keyshares = generate_keyshares(
        &opts.secret_key,
        opts.keyholders_required,
        opts.num_keyholders,
        &mut OsRng,
    )
    .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;

    for keyshare in keyshares.iter() {
        writeln!(stdout, "{}", keyshare)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use crate::party::KeyserverIdSet;

    #[test]
    fn keyshares_agree_with_original_key() {
        use crate::party::KeyserverId;
        use crate::prf::{KeyShare, Query, QueryState};
        use crate::shims::genkey;
        use std::str::FromStr;

        const KEYHOLDERS_REQUIRED: NonZeroU32 = match NonZeroU32::new(3) {
            Some(x) => x,
            None => unreachable!(),
        };
        const NUM_KEYHOLDERS: NonZeroU32 = match NonZeroU32::new(5) {
            Some(x) => x,
            None => unreachable!(),
        };
        const QUERY_STRING: &str = "Hello, world!";

        let mut stdout: Vec<u8> = vec![];
        genkey::main(&genkey::Opts {}, &mut stdout, &mut vec![]).expect("Generating key failed");
        let s = std::str::from_utf8(&stdout)
            .expect("Got invalid utf8 key")
            .trim_end();
        let key = KeyShare::from_str(s).expect("Got invalid keyshare");

        let hash = key.apply(Query::hash_from_string(QUERY_STRING));
        let hash_bytes: [u8; 32] = (&hash).into();

        let keyshare_opts = super::Opts {
            secret_key: key,
            keyholders_required: KEYHOLDERS_REQUIRED,
            num_keyholders: NUM_KEYHOLDERS,
        };

        let mut stdout: Vec<u8> = vec![];
        super::main(&keyshare_opts, &mut stdout, &mut vec![]).expect("Generating keyshares failed");
        let shares = std::str::from_utf8(&stdout)
            .expect("Invalid utf8 keyshares")
            .lines()
            .map(|l| KeyShare::from_str(l).expect("Got invalid keyshare"))
            .collect::<Vec<_>>();

        assert_eq!(shares.len(), NUM_KEYHOLDERS.get() as usize);

        let query_state =
            QueryState::new(QUERY_STRING.as_bytes(), KEYHOLDERS_REQUIRED.get() as usize);

        let keyserver_subsets = vec![
            (0, 1, 2),
            (0, 1, 3),
            (0, 1, 4),
            (0, 2, 3),
            (0, 2, 4),
            (0, 3, 4),
            (1, 2, 3),
            (1, 2, 4),
            (1, 3, 4),
            (2, 3, 4),
        ];
        for (k0, k1, k2) in keyserver_subsets {
            let mut query_state = query_state.clone();
            for k in [k0, k1, k2] {
                let coeff = KeyserverIdSet::from_iter(vec![
                    KeyserverId::try_from(k0 + 1).unwrap(),
                    KeyserverId::try_from(k1 + 1).unwrap(),
                    KeyserverId::try_from(k2 + 1).unwrap(),
                ])
                .langrange_coefficient_for_id(&KeyserverId::try_from(k + 1).unwrap());

                assert!(!query_state.has_hash());
                query_state.incorporate_response(
                    KeyserverId::try_from(k + 1).unwrap(),
                    shares[k as usize]
                        .apply_query_and_lagrange_coefficient(*query_state.query(), &coeff),
                );
            }
            assert!(query_state.has_hash());
            let completed_hash = query_state.get_hash_value().expect("Hash value");
            assert_eq!(hash_bytes, <[u8; 32]>::from(&completed_hash));
        }
    }
}
