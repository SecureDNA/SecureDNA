// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::IpAddr;

use serde::Deserialize;
use tracing::info;

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct RecaptchaResponse {
    success: bool,
    challenge_ts: Option<String>,
    hostname: Option<String>,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

pub enum RecaptchaError {
    DemoDisabled,
    /// Recaptcha endpoint wasn't reachable
    Unreachable(String),
    /// Couldn't parse the Recaptcha response
    Unparseable(String),
    /// Captcha wasn't completed correctly
    Unauthorized,
}

pub async fn validate_recaptcha(
    token: &str,
    secret: Option<&str>,
    remote_addr: IpAddr,
) -> Result<(), RecaptchaError> {
    let secret = secret.ok_or(RecaptchaError::DemoDisabled)?;
    // Avoid openssl due to potential getenv/setenv-induced UB.
    let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
    let response = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", secret.to_string()),
            ("response", token.to_string()),
            ("remoteip", format!("{remote_addr}")),
        ])
        .send()
        .await
        .map_err(|e| RecaptchaError::Unreachable(e.to_string()))?
        .json::<RecaptchaResponse>()
        .await
        .map_err(|e| RecaptchaError::Unparseable(e.to_string()))?;
    info!("recaptcha response: {response:?}");
    if response.success {
        Ok(())
    } else {
        Err(RecaptchaError::Unauthorized)
    }
}
