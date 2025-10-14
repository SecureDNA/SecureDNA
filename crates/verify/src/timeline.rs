// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use crate::rotation::Rotation;

/// A record describing when a token starts and stops being valid.
#[derive(Debug, Eq, PartialEq)]
pub struct Validity {
    /// The start of this token's validity period. (Equal to the first time it
    /// was acknowledged by any DB server.)
    start: i64,
    /// The *last* acknowledgement time for this token. This curtails a
    /// *previous* token's validity.
    last_ack: i64,
    /// The end of this token's validity period. (Equal to the `last_ack` time
    /// of the *next* token, plus a grace period which defaults to 24 hours. If
    /// there is no next token, this is `None`.)
    end: Option<i64>,
}

impl Validity {
    /// Is the token described by this record valid at the given time?
    pub fn is_valid_at(&self, time: i64) -> bool {
        match self.end {
            None => (self.start..).contains(&time),
            Some(end) => (self.start..=end).contains(&time),
        }
    }
}

/// A timeline of token validity based on a log of rotations.
///
/// Each token is valid from the first time it was acknowledged, until some
/// grace period after the last time the next token was acknowledged.
///
/// ## Example
///
/// ```
/// # use verify::rotation::Rotation;
/// # use verify::timeline::Timeline;
/// let rotations = &[
///     Rotation { time_acknowledged: 10002, server_domain: "db1.org".to_owned(), time_generated: 10000 },
///     Rotation { time_acknowledged: 10004, server_domain: "db2.org".to_owned(), time_generated: 10000 },
///     Rotation { time_acknowledged: 20007, server_domain: "db2.org".to_owned(), time_generated: 20000 },
///     Rotation { time_acknowledged: 20009, server_domain: "db1.org".to_owned(), time_generated: 20000 },
///     Rotation { time_acknowledged: 30001, server_domain: "db1.org".to_owned(), time_generated: 30000 },
///     Rotation { time_acknowledged: 30002, server_domain: "db2.org".to_owned(), time_generated: 30000 },
/// ];
///
/// // In this timeline...
/// //
/// //     * token `10000` is valid from `10002` until `Some(20059)`
/// //     * token `20000` is valid from `20007` until `Some(30052)`
/// //     * token `30000` is valid from `30001` until `None`
/// //
/// let timeline = Timeline::from_rotations(rotations, 50);
///
/// // Time 8 is before any token's validity.
/// assert!(timeline.valid_tokens(8).is_empty());
///
/// // At time 10003, token 10000 is valid, because it has been acknowledged by
/// // `db1.org`.
/// assert_eq!(timeline.valid_tokens(10003), vec![10000]);
///
/// // At time 11000, still only token 10000 is valid. It has now been
/// // acknowledged by both servers.
/// assert_eq!(timeline.valid_tokens(11000), vec![10000]);
///
/// // At time 20044, two tokens are valid. The new token 20000 has been
/// // acknowledged by both servers, but the old one is still within the
/// // 50-second grace period.
/// assert_eq!(timeline.valid_tokens(20044), vec![10000, 20000]);
///
/// // At time 22000 only token 20000 is valid. The grace period has long ended,
/// // and the old token is now rotated out.
/// assert_eq!(timeline.valid_tokens(22000), vec![20000]);
///
/// // At time 999999 only token 30000 is valid. It's been acknowledged by both
/// // servers, and there's been no next token to curtail it, so it is still
/// // "in rotation". When the token gets downloaded, it may turn out to have
/// // been expired, or otherwise invalid, but at least as far as the rotation
/// // timeline logic goes it is valid at this time.
/// assert_eq!(timeline.valid_tokens(999999), vec![30000]);
/// ```

#[derive(Debug, Eq, PartialEq)]
pub struct Timeline(BTreeMap<i64, Validity>);

impl Timeline {
    pub fn from_rotations(rotations: &[Rotation], grace_period: i64) -> Self {
        let mut validities = BTreeMap::new();

        // First, gather all the first- and last-ack times...
        for rotation in rotations {
            let entry = validities
                .entry(rotation.time_generated)
                .or_insert_with(|| Validity {
                    start: rotation.time_acknowledged,
                    last_ack: rotation.time_acknowledged,
                    end: None,
                });
            entry.start = entry.start.min(rotation.time_acknowledged);
            entry.last_ack = entry.last_ack.max(rotation.time_acknowledged);
        }

        // BTreeMap guarantees iteration is ordered by the key, which is time_generated.
        let mut end = None;
        for validity in validities.values_mut().rev() {
            validity.end = end;
            end = Some(validity.last_ack + grace_period);
        }

        Self(validities)
    }

    pub fn valid_tokens(&self, request_time: i64) -> Vec<i64> {
        self.0
            .iter()
            .filter_map(|(&token, v)| v.is_valid_at(request_time).then_some(token))
            .collect()
    }
}
