// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::hash::Hash;

use itertools::Itertools;
use time::OffsetDateTime;

pub fn combine_and_dedup_items<T: Clone + Eq + Ord + Hash>(
    items: &[T],
    other_items: &[T],
) -> Vec<T> {
    items
        .iter()
        .chain(other_items.iter())
        .cloned()
        .sorted()
        .unique()
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

#[cfg(target_arch = "wasm32")]
pub fn now_utc() -> OffsetDateTime {
    let millis = js_sys::Date::now() as i128;
    OffsetDateTime::from_unix_timestamp_nanos(millis * 1_000_000).unwrap()
}
