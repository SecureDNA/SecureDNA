// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct FetchResponse<Data = String> {
    pub data: Data,
    pub status: u16,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct FetchError {
    pub message: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<reqwest::Error> for FetchError {
    fn from(error: reqwest::Error) -> Self {
        FetchError {
            message: error.without_url().to_string(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for FetchError {
    fn from(error: wasm_bindgen::JsValue) -> Self {
        FetchError {
            message: format!("{error:?}"),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn fetch(url: &str) -> Result<FetchResponse, FetchError> {
    let response = reqwest::get(url).await?;
    let status = response.status().as_u16();
    let text = response.text().await?;
    Ok(FetchResponse { data: text, status })
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    use super::*;

    async fn do_request(url: &str, opts: RequestInit) -> Result<Response, FetchError> {
        let request = Request::new_with_str_and_init(url, &opts)?;
        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        assert!(resp_value.is_instance_of::<Response>());
        let resp: Response = resp_value.dyn_into().unwrap();

        Ok::<Response, FetchError>(resp)
    }

    pub async fn fetch(url: &str) -> Result<FetchResponse, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);
        let resp = do_request(url, opts).await?;
        let data = JsFuture::from(resp.text()?).await?.as_string().unwrap();
        let status = resp.status();
        Ok(FetchResponse { data, status })
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::fetch;
