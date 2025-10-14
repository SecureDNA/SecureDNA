// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provides cross-platform APIs for `reqwest`-based services

use std::future::Future;

use bytes::Bytes;
use hyper::body::Body;

use shared_types::requests::RequestId;

use crate::error::UnusableRequestId;

use super::util::BoxedError;

/// Return service and worker for use with SecureDNA APIs.
///
/// The given `request_id` will sent with every request. On native platforms,
/// cookies will be stored.
///
/// The returned service will be [`Send`]able, but the worker may or may not be.
/// Using the service without concurrently running the worker may hang.
pub fn securedna_service_and_worker<B>(
    request_id: RequestId,
) -> Result<
    (
        impl super::HttpService<
            B,
            Future: Send + 'static,
            ResponseBody: Body<Data = Bytes, Error = reqwest::Error> + Send,
            Error = reqwest::Error,
        >,
        impl Future<Output = ()>,
    ),
    UnusableRequestId,
>
where
    B: Body<Error: Into<BoxedError>> + Send + 'static,
{
    let (service, worker) = service_and_worker();
    let service = super::util::add_request_id(service, request_id.clone())
        .map_err(|source| UnusableRequestId { source, request_id })?;
    // Skipping on native to avoid useless per-request allocations.
    #[cfg(target_arch = "wasm32")]
    let service = super::reqwest::BrowserFetchSettings::default()
        .with_credentials()
        .adapt_service(service);
    Ok((service, worker))
}

/// Return service and worker with no default assumptions, for use with external APIs.
///
/// On native platforms, cookies will be stored.
///
/// The returned service will be [`Send`]able, but the worker may or may not be.
/// Using the service without concurrently running the worker may hang.
pub fn service_and_worker<B>() -> (
    impl super::HttpService<
        B,
        Future: Send + 'static,
        ResponseBody: Body<Data = Bytes, Error = reqwest::Error> + Send,
        Error = reqwest::Error,
    >,
    impl Future<Output = ()>,
)
where
    B: Body<Error: Into<BoxedError>> + Send + 'static,
{
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Disable pooling (hopefully temporarily) to circumvent deadlock in `doprf_client`.
        // The `doprf_client` integration tests (e.g. test_hdb) occasionally deadlock (sometimes
        // 1% of runs fail, other times half of all runs fail), usually when requesting `/open`
        // for ET hashes. Rather than hanging indefinitely, the tests take 2 minutes because
        // surrounding code detects the problem and retries the connections. I'm currently
        // leaning towards this being a bug with `reqwest` but I'm not certain, as I've had
        // difficulty building a minimal reproducible test case.
        //
        // As for the underlying cause... the deadlock happens after a connection is grabbed from
        // the pool, but before the request body is polled; it is suspended on this line:
        // https://github.com/hyperium/hyper/blob/ea5b49b7d4e18c1eaa7f42db0ff91d1dcca56a04/src/client/conn/http1.rs#L228
        // AFAICT, it seems like it happened due to returning a `/keyserve` connection to the pool
        // as soon as its response headers came in, whereas it should have waited until the
        // connection was idle. Thus I'm tempted to call it a bug in `reqwest`.
        //
        // That interacts poorly with `doprf_client` because it opens multiple concurrent streaming
        // connections to the same keyserver (regular hashes and ET hashes), and re-using the
        // connection causes the later request to be queued behind the first, but the first request
        // can't finish until its response is consumed by the HDB, which can't happen until the
        // second request starts. Thus, a cyclic dependency and deadlock.
        //
        // Fortunately, an easy workaround is to disable pooling; can't have two different tasks
        // using the same connection if connections aren't reused. We tend to have a few large
        // requests so hopefully the performance costs are minor. The plan is to get a release
        // out with important new features and large performance improvements, then return to
        // hunt down the root cause when we have more time.
        let pool_size = 0;

        let client = reqwest::Client::builder()
            .use_rustls_tls() // Avoid openssl due to potential getenv/setenv-induced UB.
            .pool_max_idle_per_host(pool_size)
            .cookie_store(true)
            .build()
            .expect("Unable to create reqwest::Client with cookie-store");
        (super::reqwest::native_service(client), async {})
    }
    #[cfg(target_arch = "wasm32")]
    {
        let client = reqwest::Client::new();
        let service = super::reqwest::compatible_service(client);
        super::util::outsourced(service)
    }
}
