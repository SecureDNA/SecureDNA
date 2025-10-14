// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use bytes::Bytes;
use futures::lock::Mutex;
use http_body_util::{BodyExt, Full};
use http_client::{service::util::BoxedError, BaseApiClient};
use hyper::{
    header::{HeaderValue, CONTENT_TYPE},
    Request, Response, StatusCode,
};
use minhttp::response::GenericResponse;
use std::collections::HashMap;
use url::Url;

/// Proxies requests from synthclient to the web interface,
/// and caches the requested pages and assets.
pub struct WebCache {
    http_client: BaseApiClient,
    frontend_url: Url,

    /// A HashMap from paths like "/v1/web-interface/foobar.js" to pairs of
    /// Content-Type and body.
    cache: Mutex<HashMap<String, (HeaderValue, Bytes)>>,
}

impl WebCache {
    pub fn new(http_client: BaseApiClient, frontend_url: Url) -> Self {
        Self {
            http_client,
            frontend_url,
            cache: Default::default(),
        }
    }

    pub async fn get(&self, path: &str) -> Result<GenericResponse, BoxedError> {
        let path = match path {
            "" | "/" | "/index.html" => self.frontend_url.path(),
            path => path,
        };

        // If `self.frontend_url` is https://example.org/foo(/), then we want to allow
        // the paths `/foo` and `/foo/*` and `/favicon.ico`, but nothing else.
        let allowed_base = self.frontend_url.path().trim_end_matches('/');
        let allowed_prefix = allowed_base.to_string() + "/";
        if path == allowed_base || path.starts_with(&allowed_prefix) || path == "/favicon.ico" {
            // This path is allowed; continue.
        } else {
            return Err("Path is not part of web interface".into());
        }

        let cached = { self.cache.lock().await.get(path).cloned() };

        let (content_type, body) = match cached {
            Some(pair) => pair,
            None => {
                let mut uri = self.frontend_url.clone();
                uri.set_path(path);
                let request = Request::get(uri.as_str()).body(())?;
                let response: Response<Bytes> = self.http_client.request(request).await?;
                let (head, body) = response.into_parts();
                let content_type = head
                    .headers
                    .get(CONTENT_TYPE)
                    .cloned()
                    .unwrap_or(HeaderValue::from_static("application/octet-stream"));
                self.cache
                    .lock()
                    .await
                    .insert(path.to_string(), (content_type.clone(), body.clone()));
                (content_type, body)
            }
        };

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, content_type.clone())
            .body(Full::from(body.clone()).boxed())?;

        let response = response.map(|body| BodyExt::map_err(body, anyhow::Error::from).boxed());

        Ok(response)
    }
}
