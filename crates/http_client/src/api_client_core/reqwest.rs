// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use bytes::Bytes;
use tracing::debug;

use crate::error::HTTPError;
use shared_types::requests::RequestId;
use streamed_ristretto::reqwest::check_content_type;

#[derive(Debug, Clone)]
pub struct ApiClientCore {
    client: reqwest::Client, // cheaply cloneable (Arc<...> internally), see docs
}

impl ApiClientCore {
    pub fn new(request_id: RequestId) -> Self {
        let mut default_headers = reqwest::header::HeaderMap::with_capacity(3);
        default_headers.insert(
            "X-Request-ID",
            reqwest::header::HeaderValue::from_str(&request_id.0).unwrap_or(
                reqwest::header::HeaderValue::from_static("non-ascii request id"),
            ),
        );

        let client = reqwest::ClientBuilder::new()
            .default_headers(default_headers)
            .cookie_store(true)
            .build()
            .unwrap(); // this only fails if the system config is messed up, isn't recoverable

        Self { client }
    }

    /// Construct a new ApiClientCore with no default headers / assumptions, for use with external APIs
    pub fn new_external() -> Self {
        Self {
            client: reqwest::ClientBuilder::new()
                .cookie_store(true)
                .build()
                .unwrap(), // See `Self::new()`, can't fail in normal circumstances
        }
    }

    /// Get or post a given body to a given url with a given content type, and optional extra headers.
    /// The response type will be verified against `expected_content_type`.
    pub(crate) async fn raw_request(
        &self,
        url: &str,
        body: Option<Bytes>,
        content_type: &'static str,
        header_iter: &[(String, String)],
        expected_content_type: &'static str,
    ) -> Result<bytes::Bytes, HTTPError> {
        let mut rb = match body {
            Some(b) => self
                .client
                .post(url)
                .body(b)
                .header(reqwest::header::CONTENT_TYPE, content_type),
            None => self.client.get(url),
        };

        for (key, value) in header_iter {
            rb = rb.header(key, value)
        }

        debug!("http_client: requesting {url}");

        let response = rb.send().await.map_err(|e| HTTPError::RequestError {
            ctx: format!("requesting {url}"),
            retriable: true,
            source: Box::new(e),
        })?;

        debug!("http_client: response from {url:?}: {}", response.status());

        let retriable = super::status_code::is_retriable(response.status().as_u16());

        let body = async {
            let status = response.status();
            let content_type_err = check_content_type(response.headers(), expected_content_type);
            let bytes = response.bytes().await?;

            if content_type_err.is_err() {
                Err(format!(
                    "{status}: {}: {}",
                    content_type_err.unwrap_err(),
                    String::from_utf8_lossy(&bytes)
                )
                .into())
            } else if status.is_client_error() || status.is_server_error() {
                Err(format!("{status}: {}", String::from_utf8_lossy(&bytes)).into())
            } else {
                Ok(bytes)
            }
        };
        body.await.map_err(|e| HTTPError::RequestError {
            ctx: format!("requesting {url}"),
            retriable,
            source: e,
        })
    }
}
