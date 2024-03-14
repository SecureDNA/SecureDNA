// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{collections::HashMap, hash::Hash, time::SystemTime};

pub trait TimeSlotProvider {
    /// The current time slot number, used as a bucket for rate-limiting requests.
    fn current_time_slot(&self) -> u64;

    /// A string description of the time unit each time slot corresponds to.
    fn describe_time_unit(&self) -> &'static str;
}

/// A TimeSlotProvider assigning a time slot to each hour of system time.
pub struct SystemTimeHourProvider;

impl TimeSlotProvider for SystemTimeHourProvider {
    fn current_time_slot(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 3600
    }

    fn describe_time_unit(&self) -> &'static str {
        "hour"
    }
}

/// A map that tracks how many requests were made for each key in the current
/// time slot. No key can make more than `limit` requests.
pub struct RateLimiter<K, P> {
    time_slot_provider: P,
    time_slot: u64,
    requests: HashMap<K, usize>,
    limit: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RateLimitExceeded {
    pub limit: usize,
    pub unit: &'static str,
}

impl<K, P> RateLimiter<K, P>
where
    K: Eq + Hash,
    P: TimeSlotProvider,
{
    /// Create a new RateLimiter allowing up to `limit` requests per time slot.
    pub fn new(limit: usize, time_slot_provider: P) -> Self {
        let time_slot = time_slot_provider.current_time_slot();
        Self {
            time_slot_provider,
            time_slot,
            requests: HashMap::new(),
            limit,
        }
    }

    /// Count a request for the given key, and return an error if this request
    /// exceeds the rate limit.
    pub fn request(&mut self, key: K) -> Result<(), RateLimitExceeded> {
        let current = self.time_slot_provider.current_time_slot();
        if current != self.time_slot {
            self.time_slot = current;
            self.requests.clear();
        }
        let entry = self.requests.entry(key).or_default();
        if *entry >= self.limit {
            return Err(RateLimitExceeded {
                limit: self.limit,
                unit: self.time_slot_provider.describe_time_unit(),
            });
        }
        *entry += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::rate_limiter::RateLimitExceeded;

    use super::{RateLimiter, TimeSlotProvider};

    struct MockTimeProvider {
        hour: u64,
    }

    impl TimeSlotProvider for MockTimeProvider {
        fn current_time_slot(&self) -> u64 {
            self.hour
        }

        fn describe_time_unit(&self) -> &'static str {
            "hour"
        }
    }

    #[test]
    fn test_rate_limit() {
        let provider = MockTimeProvider { hour: 1111 };
        let mut rate_limiter = RateLimiter::<&str, _>::new(3, provider);
        let err = RateLimitExceeded {
            limit: 3,
            unit: "hour",
        };

        // A key can make a limited number of requests in an hour.
        assert_eq!(rate_limiter.request("Alice"), Ok(()));
        assert_eq!(rate_limiter.request("Alice"), Ok(()));
        assert_eq!(rate_limiter.request("Bob"), Ok(()));
        assert_eq!(rate_limiter.request("Alice"), Ok(()));
        assert_eq!(rate_limiter.request("Alice"), Err(err));
        assert_eq!(rate_limiter.request("Alice"), Err(err));
        assert_eq!(rate_limiter.request("Bob"), Ok(()));
        assert_eq!(rate_limiter.request("Bob"), Ok(()));
        assert_eq!(rate_limiter.request("Bob"), Err(err));
        assert_eq!(rate_limiter.request("Bob"), Err(err));

        // When the hour advances, the rate limits reset.
        rate_limiter.time_slot_provider.hour += 1;
        assert_eq!(rate_limiter.request("Alice"), Ok(()));
        assert_eq!(rate_limiter.request("Alice"), Ok(()));
        assert_eq!(rate_limiter.request("Alice"), Ok(()));
        assert_eq!(rate_limiter.request("Alice"), Err(err));
    }
}
