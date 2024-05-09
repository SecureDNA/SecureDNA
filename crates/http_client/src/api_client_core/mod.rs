// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod status_code;

#[cfg_attr(target_arch = "wasm32", path = "web_sys.rs")]
#[cfg_attr(not(target_arch = "wasm32"), path = "reqwest.rs")]
pub mod implementation;

use bytes::Bytes;

pub use self::implementation::ApiClientCore as ApiClientCoreImpl;
use crate::error::HttpError;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ApiClientCore {
    async fn raw_request(
        &self,
        url: &str,
        body: Option<Bytes>,
        content_type: &'static str,
        headers: &[(String, String)],
        expected_content_type: &'static str,
    ) -> Result<bytes::Bytes, HttpError>;
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ApiClientCore for ApiClientCoreImpl {
    async fn raw_request(
        &self,
        url: &str,
        body: Option<Bytes>,
        content_type: &'static str,
        headers: &[(String, String)],
        expected_content_type: &'static str,
    ) -> Result<bytes::Bytes, HttpError> {
        self.raw_request(url, body, content_type, headers, expected_content_type)
            .await
    }
}

pub mod test_utils {
    use super::*;

    use std::pin::Pin;

    type ResultFuture = dyn futures::Future<Output = Result<bytes::Bytes, HttpError>> + Send;
    type Responder = dyn (Fn(String, Option<Bytes>, String, Vec<(String, String)>, String) -> Pin<Box<ResultFuture>>)
        + Send
        + Sync;

    /// Mock `ApiClientCore` that holds a closure that can respond to requests with fake responses, or errors.
    ///
    /// ```rust
    /// use futures::FutureExt;
    ///
    /// use http_client::{BaseApiClient, HttpError};
    /// use http_client::test_utils::ApiClientCoreMock;
    ///
    /// let mock = ApiClientCoreMock::from(|url: String, _body, _content_type, _headers, _expected_content_type| {
    ///     // note the `async { ... }.boxed()`!
    ///     async {
    ///         if url.contains("coffee") {
    ///             Err(HttpError::RequestError {
    ///                 ctx: url,
    ///                 status: Some(418),
    ///                 retriable: true,
    ///                 source: "i'm a teapot".into(),
    ///             })
    ///         } else {
    ///             tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    ///             Ok("\"earl grey, hot\"".as_bytes().into())
    ///         }
    ///     }.boxed()
    /// });
    /// let client = BaseApiClient::from(mock);
    ///
    /// // use the mocked client as desired
    /// let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    /// rt.block_on(async {
    ///     client.json_json_post::<_, String>("example.com/tea", &"please").await.unwrap();
    ///     client.json_json_post::<_, String>("example.com/coffee", &"pls").await.unwrap_err();
    /// });
    /// ```
    pub struct ApiClientCoreMock {
        responder: Box<Responder>,
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl ApiClientCore for ApiClientCoreMock {
        async fn raw_request(
            &self,
            url: &str,
            body: Option<Bytes>,
            content_type: &'static str,
            headers: &[(String, String)],
            expected_content_type: &'static str,
        ) -> Result<bytes::Bytes, HttpError> {
            (self.responder)(
                url.into(),
                body,
                content_type.into(),
                headers.into(),
                expected_content_type.into(),
            )
            .await
        }
    }

    impl<
            F: Fn(
                    String,
                    Option<Bytes>,
                    String,
                    Vec<(String, String)>,
                    String,
                ) -> Pin<Box<ResultFuture>>
                + Send
                + Sync
                + 'static,
        > From<F> for ApiClientCoreMock
    {
        fn from(value: F) -> Self {
            Self {
                responder: Box::new(value),
            }
        }
    }
}
