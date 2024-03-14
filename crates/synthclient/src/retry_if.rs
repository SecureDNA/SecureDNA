// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use again::RetryPolicy;
use futures::Future;
use std::time::Duration;

const PHI_OVER_SQRT_5: f64 = 0.72360679775;
const PHI: f64 = 1.61803398875;

pub async fn retry_if<Value, Error, A, C, F>(action: A, should_retry: C) -> Result<Value, Error>
where
    F: Future<Output = Result<Value, Error>>,
    A: FnMut() -> F,
    C: Fn(&Error) -> bool,
    Error: std::fmt::Debug,
{
    // We had Fibonacci backoff before, but `again` only offers exponential backoff.
    // No problem! An exponential backoff by factor φ starting from φ/√5 is *very* close.
    // (This can be derived from the closed form of the Fibonacci series.)

    let policy = RetryPolicy::exponential(Duration::from_secs_f64(PHI_OVER_SQRT_5))
        .with_backoff_exponent(PHI)
        .with_max_retries(12)
        .with_max_delay(Duration::from_secs(34))
        .with_jitter(true);

    policy.retry_if(action, should_retry).await
}
