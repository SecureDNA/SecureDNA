// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use again::RetryPolicy;
use futures::{Future, FutureExt};
use std::time::Duration;

use crate::error::DOPRFError;

const PHI_OVER_SQRT_5: f64 = 0.72360679775;
const PHI: f64 = 1.61803398875;

/// We had Fibonacci backoff before, but `again` only offers exponential backoff.
/// No problem! An exponential backoff by factor φ starting from φ/√5 is *very* close.
/// (This can be derived from the closed form of the Fibonacci series.)
///
/// Returns a policy with this approximation and jitter.
pub fn retry_policy_jittered_fibonacci() -> RetryPolicy {
    RetryPolicy::exponential(Duration::from_secs_f64(PHI_OVER_SQRT_5))
        .with_backoff_exponent(PHI)
        .with_jitter(true)
}

/// Default `retry_if` policy using `retry_policy_jittered_fibonacci`, 12 max retries, and
/// 34 seconds of maximum delay between retries.
///
/// This function can wait a very long time for success, if quick failure is preferred
/// a custom policy should be used.
pub async fn retry_if<Value, Error, A, C, F>(action: A, should_retry: C) -> Result<Value, Error>
where
    F: Future<Output = Result<Value, Error>>,
    A: FnMut() -> F,
    C: Fn(&Error) -> bool,
    Error: std::fmt::Debug,
{
    let policy = retry_policy_jittered_fibonacci()
        .with_max_retries(12)
        .with_max_delay(Duration::from_secs(34));

    policy.retry_if(action, should_retry).await
}

/// Add a timeout of `duration` to the given `DOPRFError`-returning future.
/// If the timeout is exceeded, a retriable "timed out" `DOPRFError::RequestError`
/// will be returned.
pub async fn with_timeout<F, Value>(duration: Duration, future: F) -> Result<Value, DOPRFError>
where
    F: Future<Output = Result<Value, DOPRFError>>,
{
    let mut future = Box::pin(future).fuse();
    let mut delay = futures_timer::Delay::new(duration).fuse();
    futures::select_biased! {
        res = future => res,
        _ = delay => Err(DOPRFError::Timeout { after: duration })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_error_works() {
        let start = crate::instant::get_now();

        let r = with_timeout(Duration::from_secs(1), async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        })
        .await
        .unwrap_err();

        println!("err: {r}");

        let elapsed = start.elapsed();

        assert!(r.is_retriable());
        assert!(r.to_string().contains("Timed out"));
        assert!(elapsed < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn timeout_success_works() {
        let start = crate::instant::get_now();

        with_timeout(Duration::from_secs(10), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        })
        .await
        .unwrap();

        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(2));
    }
}
