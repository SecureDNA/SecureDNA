// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;

use crate::api_client_core::{ApiClientCore, ApiClientCoreImpl};
use crate::error::HttpError;
use packed_ristretto::{PackableRistretto, PackedRistrettos};
use shared_types::info_with_timestamp;
use shared_types::requests::RequestId;
use streamed_ristretto::{stream::check_content_length, HasContentType};

/// Helper for querying internal servers (HDB and keyservers)
#[derive(Clone)]
pub struct BaseApiClient {
    // 99% of the time this is going to be ApiClientCoreImpl, but it's overrideable for mocking purposes
    // ApiClientCoreImpl is the platform-dependent, reqwest (native) or web-sys (wasm) implmentation
    core: Arc<dyn ApiClientCore + Send + Sync>,
}

impl<Core: ApiClientCore + Send + Sync + 'static> From<Core> for BaseApiClient {
    fn from(core: Core) -> Self {
        Self {
            core: Arc::new(core),
        }
    }
}

// constructors for the usual case where we're using ApiClientCoreImpl
impl BaseApiClient {
    /// Construct a new ApiClient for the given RequestId. It will attach this
    /// id to each request it makes.
    pub fn new(request_id: RequestId) -> Self {
        ApiClientCoreImpl::new(request_id).into()
    }

    /// Construct a new ApiClient for use with external APIs: it won't set any headers
    /// or handle API keys.
    pub fn new_external() -> Self {
        ApiClientCoreImpl::new_external().into()
    }

    /// Post ristrettos, get JSON. Returns error for >=400 status.
    pub async fn ristretto_json_post<I, O>(
        &self,
        url: &str,
        packed_ristrettos: &PackedRistrettos<I>,
    ) -> Result<O, HttpError>
    where
        I: PackableRistretto + HasContentType,
        O: serde::de::DeserializeOwned,
        for<'a> &'a I::Array: IntoIterator<Item = &'a u8>,
    {
        let body: Vec<_> = packed_ristrettos
            .iter_encoded()
            .flatten()
            .copied()
            .collect();
        let bytes = self
            .raw_post(url, body.into(), I::CONTENT_TYPE, &[], "application/json")
            .await?;

        serde_json::from_slice(&bytes).map_err(|e| {
            let error_text = format_serde_error_from_bytes(bytes.into(), e);
            HttpError::DecodeError {
                decoding: format!("json from {url}"),
                source: error_text.into(),
            }
        })
    }

    /// Get JSON. Returns error for >=400 status.
    pub async fn json_get<O: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<O, HttpError> {
        let bytes = self.raw_get(url, &[], "application/json").await?;
        serde_json::from_slice(&bytes).map_err(|e| {
            let error_text = format_serde_error_from_bytes(bytes.into(), e);
            HttpError::DecodeError {
                decoding: format!("json from {url}"),
                source: error_text.into(),
            }
        })
    }

    /// Post JSON, get JSON. Returns error for >=400 status.
    pub async fn json_json_post<I: serde::Serialize, O: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        payload: &I,
    ) -> Result<O, HttpError> {
        let body = serde_json::to_vec(payload).map_err(|e| HttpError::RequestError {
            ctx: format!("serializing payload for json_json_post to {url}"),
            status: None,
            retriable: false,
            source: Box::new(e),
        })?;
        self.bytes_json_post(url, body.into(), "application/json")
            .await
    }

    /// Post ristrettos, get ristrettos. Returns error for >=400 status.
    #[allow(dead_code)]
    pub async fn ristretto_ristretto_post<I, O>(
        &self,
        url: &str,
        packed_ristrettos: &PackedRistrettos<I>,
    ) -> Result<PackedRistrettos<O>, HttpError>
    where
        I: PackableRistretto + HasContentType,
        O: PackableRistretto + HasContentType + 'static,
        for<'a> &'a I::Array: IntoIterator<Item = &'a u8>,
    {
        self.ristretto_ristretto_post_with_headers(url, packed_ristrettos, &[])
            .await
    }

    /// Post ristrettos, get ristrettos (with custom headers). Returns error for >=400 status.
    pub async fn ristretto_ristretto_post_with_headers<I, O>(
        &self,
        url: &str,
        packed_ristrettos: &PackedRistrettos<I>,
        headers: &[(String, String)],
    ) -> Result<PackedRistrettos<O>, HttpError>
    where
        I: PackableRistretto + HasContentType,
        O: PackableRistretto + HasContentType + 'static,
        for<'a> &'a I::Array: IntoIterator<Item = &'a u8>,
    {
        let body: Vec<_> = packed_ristrettos
            .iter_encoded()
            .flatten()
            .copied()
            .collect();

        let bytes = self
            .raw_post(url, body.into(), I::CONTENT_TYPE, headers, O::CONTENT_TYPE)
            .await?;

        let content_len = bytes.len().try_into().ok();
        check_content_length(content_len, O::SIZE).map_err(|e| HttpError::DecodeError {
            decoding: format!("decoding ristretto points from {url}"),
            source: e.into(),
        })?;

        let packed_ristrettos = bytes
            .chunks_exact(O::SIZE)
            .map(|c| <O::Array>::try_from(c).ok().unwrap())
            .collect();
        Ok(packed_ristrettos)
    }
    /// Post bytes, get bytes. Bring your own content-type. Returns error for >=400 status.
    pub async fn bytes_bytes_post(
        &self,
        url: &str,
        body: Bytes,
        content_type: &'static str,
        expected_content_type: &'static str,
    ) -> Result<Bytes, HttpError> {
        self.raw_post(url, body, content_type, &[], expected_content_type)
            .await
    }

    /// Post bytes, get JSON. Bring your own content-type. Returns error for >=400 status.
    pub async fn bytes_json_post<O: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: Bytes,
        content_type: &'static str,
    ) -> Result<O, HttpError> {
        let bytes = self
            .bytes_bytes_post(url, body, content_type, "application/json")
            .await?;

        serde_json::from_slice(&bytes).map_err(|e| {
            let error_text = format_serde_error_from_bytes(bytes.into(), e);
            HttpError::DecodeError {
                decoding: format!("json from {url}"),
                source: error_text.into(),
            }
        })
    }

    pub(crate) async fn raw_post(
        &self,
        url: &str,
        body: Bytes,
        content_type: &'static str,
        header_iter: &[(String, String)],
        expected_content_type: &'static str,
    ) -> Result<bytes::Bytes, HttpError> {
        self.core
            .raw_request(
                url,
                Some(body),
                content_type,
                header_iter,
                expected_content_type,
            )
            .await
    }

    pub(crate) async fn raw_get(
        &self,
        url: &str,
        header_iter: &[(String, String)],
        expected_content_type: &'static str,
    ) -> Result<bytes::Bytes, HttpError> {
        self.core
            .raw_request(url, None, "", header_iter, expected_content_type)
            .await
    }
}

impl fmt::Debug for BaseApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseApiClient").finish_non_exhaustive()
    }
}

/// Helper for local testing: rewrites all URLs requested by this client from https:// to http://,
/// to hit non-TLS local servers
pub struct HttpsToHttpRewriter {
    inner: Arc<dyn ApiClientCore + Send + Sync + 'static>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ApiClientCore for HttpsToHttpRewriter {
    async fn raw_request(
        &self,
        url: &str,
        body: Option<Bytes>,
        content_type: &'static str,
        headers: &[(String, String)],
        expected_content_type: &'static str,
    ) -> Result<bytes::Bytes, HttpError> {
        let new_url = url.replace("https://", "http://");
        info_with_timestamp!(
            "api_client::HttpsToHttpRewriter: rewrote {} to {} for local testing",
            url,
            new_url
        );
        self.inner
            .raw_request(&new_url, body, content_type, headers, expected_content_type)
            .await
    }
}

impl HttpsToHttpRewriter {
    /// Inject this layer in between the normal client and the inner core to do the URL rewriting
    pub fn inject(client: BaseApiClient) -> BaseApiClient {
        let BaseApiClient { core } = client;
        BaseApiClient {
            core: Arc::new(Self { inner: core }),
        }
    }
}

fn format_serde_error_from_bytes(
    bytes: Vec<u8>,
    e: impl Into<format_serde_error::ErrorTypes>,
) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => format_serde_error::SerdeError::new(text, e).to_string(),
        Err(err) => err.to_string(),
    }
}
