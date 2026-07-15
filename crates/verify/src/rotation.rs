// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Eq, PartialEq)]
pub struct Rotation {
    pub time_acknowledged: i64,
    pub server_domain: String,
    pub time_generated: i64,
}

impl FromStr for Rotation {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let [ack, domain, time_gen] = s.split_ascii_whitespace().collect::<Vec<_>>()[..] else {
            return Err("rotation record does not have three fields");
        };
        Ok(Self {
            time_acknowledged: ack
                .parse()
                .map_err(|_| "could not parse acknowledge timestamp")?,
            server_domain: domain.to_owned(),
            time_generated: time_gen
                .parse()
                .map_err(|_| "could not parse generate timestamp")?,
        })
    }
}

#[derive(Debug, Eq, PartialEq, Error)]
#[error("parse error at {line_number}: {error}")]
pub struct RotationParseError {
    line_number: usize,
    error: &'static str,
}

pub fn parse_rotations(log: &str) -> Result<Vec<Rotation>, RotationParseError> {
    log.lines()
        .zip(1..)
        .filter(|(line, _)| !line.trim().is_empty())
        .map(|(line, line_number)| {
            Rotation::from_str(line).map_err(|error| RotationParseError { line_number, error })
        })
        .collect::<Result<Vec<Rotation>, _>>()
}

#[cfg(test)]
mod tests {
    use crate::rotation::{Rotation, RotationParseError, parse_rotations};

    #[test]

    fn can_parse_rotations() {
        assert_eq!(
            parse_rotations(
                "1743989774\t9.db.dev.securedna.org\t1743989773
1743990722\t9.db.dev.securedna.org\t1743990721
1744001054\t9.db.dev.securedna.org\t1744000817
1744001770\t9.db.dev.securedna.org\t1744001643
1744002254\t9.db.dev.securedna.org\t1744002102"
            ),
            Ok(vec![
                Rotation {
                    time_acknowledged: 1743989774,
                    server_domain: "9.db.dev.securedna.org".to_owned(),
                    time_generated: 1743989773
                },
                Rotation {
                    time_acknowledged: 1743990722,
                    server_domain: "9.db.dev.securedna.org".to_owned(),
                    time_generated: 1743990721
                },
                Rotation {
                    time_acknowledged: 1744001054,
                    server_domain: "9.db.dev.securedna.org".to_owned(),
                    time_generated: 1744000817
                },
                Rotation {
                    time_acknowledged: 1744001770,
                    server_domain: "9.db.dev.securedna.org".to_owned(),
                    time_generated: 1744001643
                },
                Rotation {
                    time_acknowledged: 1744002254,
                    server_domain: "9.db.dev.securedna.org".to_owned(),
                    time_generated: 1744002102
                },
            ])
        );

        assert_eq!(
            parse_rotations("1\ta.com\t2\nblah\n"),
            Err(RotationParseError {
                line_number: 2,
                error: "rotation record does not have three fields"
            })
        );
    }
}
