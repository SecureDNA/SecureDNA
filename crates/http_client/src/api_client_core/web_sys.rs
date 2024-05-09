// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fmt::Display;

use bytes::Bytes;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCredentials, RequestInit, RequestMode, Response};

use crate::error::HttpError;
use shared_types::requests::RequestId;
use streamed_ristretto::web_sys::check_content_type;

impl From<wasm_bindgen::JsValue> for HttpError {
    fn from(value: wasm_bindgen::JsValue) -> Self {
        HttpError::JsError {
            error: format!("{value:?}"),
        }
    }
}

#[derive(Debug)]
pub struct WebFetchError {
    status: Option<u16>,
}

impl Error for WebFetchError {}

impl Display for WebFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebAssembly fetch() failed: ")?;
        match self.status {
            None => write!(f, "no response"),
            Some(status) => write!(f, "response status {status}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiClientCore {
    request_id: Option<RequestId>,
}

impl ApiClientCore {
    pub fn new(request_id: RequestId) -> Self {
        Self {
            request_id: Some(request_id),
        }
    }

    /// Construct a new ApiClientCore with no default headers / assumptions, for use with external APIs
    pub fn new_external() -> Self {
        Self { request_id: None }
    }

    /// Get, or post a given body to, a given url with a given content type, and optional extra headers.
    /// The response type will be verified against `expected_content_type`.
    pub(crate) async fn raw_request(
        &self,
        url: &str,
        body: Option<Bytes>,
        content_type: &'static str,
        header_iter: &[(String, String)],
        expected_content_type: &'static str,
    ) -> Result<bytes::Bytes, HttpError> {
        let length = match &body {
            Some(b) => b.len() as u32,
            None => 0,
        };
        let body_array = js_sys::Uint8Array::new_with_length(length);
        let mut opts = RequestInit::new();
        let headers = Headers::new()?;
        opts.mode(RequestMode::Cors);
        opts.credentials(RequestCredentials::Include);
        if let Some(b) = body {
            body_array.copy_from(&b);
            opts.method("POST");
            opts.body(Some(&body_array.buffer()));
            headers.set("Content-Type", content_type)?;
        } else {
            opts.method("GET");
        }

        if let Some(request_id) = &self.request_id {
            headers.set("X-Request-ID", &request_id.0)?;
        }

        for (key, value) in header_iter {
            headers.set(key, value)?;
        }
        opts.headers(&headers);
        let request = Request::new_with_str_and_init(url, &opts)?;

        let resp_value = match (
            js_sys::global().dyn_into::<web_sys::Window>(),
            js_sys::global().dyn_into::<web_sys::DedicatedWorkerGlobalScope>(),
        ) {
            (Ok(global), _) => JsFuture::from(global.fetch_with_request(&request)).await,
            (_, Ok(global)) => JsFuture::from(global.fetch_with_request(&request)).await,
            _ => panic!("No global object!"),
        }
        .map_err(|_e| HttpError::RequestError {
            ctx: format!("posting {content_type} from WebAssembly"),
            status: None,
            retriable: true,
            source: Box::new(WebFetchError { status: None }),
        })?;

        assert!(resp_value.is_instance_of::<Response>());
        let resp: Response = resp_value.dyn_into().unwrap();
        let status = resp.status();

        if status >= 400 {
            return Err(HttpError::RequestError {
                ctx: format!("posting {content_type} from WebAssembly"),
                status: Some(status),
                retriable: super::status_code::is_retriable(resp.status()),
                source: Box::new(WebFetchError {
                    status: Some(resp.status()),
                }),
            });
        }

        check_content_type(&resp.headers(), expected_content_type).map_err(|e| {
            HttpError::RequestError {
                ctx: format!("got wrong content type back posting ristrettos to {url}"),
                status: Some(status),
                retriable: false,
                source: e.into(),
            }
        })?;

        // Convert this other `Promise` into a rust `Future`.
        let buffer = JsFuture::from(resp.array_buffer()?).await?;
        // Send the JSON response back to JS.
        let array = js_sys::Uint8Array::new(&buffer);
        Ok(bytes::Bytes::from(array.to_vec()))
    }
}
