// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::Cow;

use quickdna::{FastaParseError::ParseError, TranslationError::BadNucleotide};
use serde::{Deserialize, Serialize};

use certificates::{ChainItem, Exemption, Role, TokenBundleError};
use doprf_client::error::DoprfError;
use http_client::{HttpError, UnusableRequestId};
use shared_types::error::InvalidClientTokenBundle;

use crate::{ncbi::NcbiError, parsefasta::CheckFastaError, rate_limiter::RateLimitExceeded};

/// Error type that will be serialized as API response, as opposed to logged.
/// Internal errors should be transformed to this type with that in mind
/// (sticking to standard formatting, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "diagnostic", rename_all = "snake_case")]
// tsgen = { diagnostic: string, additional_info: string, line_number_range?: [number, number] | null }
pub enum ApiError {
    NotFound(Fields),
    InternalServerError(Fields),
    Unauthorized(Fields),
    InvalidInput(Fields),
    RequestTooBig(Fields),
    TooManyRequests(Fields),
}

impl ApiError {
    pub fn status_code(&self) -> u16 {
        match self {
            // trying to not take a server dependency here
            Self::NotFound(_) => 404,
            Self::InternalServerError(_) => 500,
            Self::Unauthorized(_) => 401,
            Self::InvalidInput(_) => 400,
            Self::RequestTooBig(_) => 413,
            Self::TooManyRequests(_) => 429,
        }
    }

    pub fn additional_info(&self) -> &str {
        match self {
            ApiError::NotFound(f)
            | ApiError::InternalServerError(f)
            | ApiError::Unauthorized(f)
            | ApiError::InvalidInput(f)
            | ApiError::RequestTooBig(f)
            | ApiError::TooManyRequests(f) => &f.additional_info,
        }
    }
}

/// Error type that will be serialized as API response, as opposed to logged.
/// Internal errors should be transformed to this type with that in mind
/// (sticking to standard formatting, etc.)
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "diagnostic", rename_all = "snake_case")]
// tsgen = { diagnostic: string, additional_info: string, line_number_range?: [number, number] | null }
pub enum ApiWarning {
    CertificateExpiringSoon(Fields),
    TooShort(Fields),
    TooAmbiguous(Fields),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Fields {
    // DO NOT MAKE THESE FIELDS PUBLIC!
    // They're private so that errors must be constructed in this file, for consistency.
    additional_info: Cow<'static, str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    line_number_range: Option<(u64, u64)>,
}

impl Fields {
    /// Intentionally private.
    fn new(value: impl Into<Cow<'static, str>>) -> Self {
        Self {
            additional_info: value.into(),
            line_number_range: None,
        }
    }
}

impl ApiWarning {
    pub fn certificate_expiring_soon<R: Role>(item: ChainItem<R>) -> Self {
        Self::CertificateExpiringSoon(Fields::new(format!("{}.", item.expiring_soon_text())))
    }

    pub fn too_short() -> Self {
        Self::TooShort(Fields::new(
            "Permission was granted because the order was too short for SecureDNA to detect hazards."
        ))
    }

    pub fn too_ambiguous() -> Self {
        Self::TooAmbiguous(Fields::new(
            "Permission was granted because the order was too ambiguous for SecureDNA to detect hazards."
        ))
    }
}

impl ApiError {
    pub fn not_found(uri: impl std::fmt::Display) -> Self {
        Self::NotFound(Fields::new(format!("{uri} was not found.")))
    }

    pub fn root_not_found(uri: impl std::fmt::Display) -> Self {
        Self::NotFound(Fields::new(format!("Failed to load the web interface from {uri}. If that page is otherwise reachable, your network configuration may be preventing synthclient from accessing the internet.")))
    }

    pub fn generic_internal_server_error() -> Self {
        Self::InternalServerError(Fields::new("Unexpected internal error."))
    }

    pub fn request_body_too_big(max: u64) -> Self {
        Self::RequestTooBig(Fields::new(format!(
            "The JSON request body exceeds the maximum allowed size of {max} bytes."
        )))
    }

    pub fn request_lacks_content_length() -> Self {
        Self::InvalidInput(Fields::new(
            "The JSON request lacks a Content-Length header.",
        ))
    }
}

pub(crate) const BAD_NUCLEOTIDE_HINT: &str = "If this is a modified base, please see \
    https://github.com/SecureDNA/tools where you can find a selection of filters to transform \
    particular vendors' proprietary formats into the generic format which synthclient handles.";

impl From<CheckFastaError> for ApiError {
    fn from(err: CheckFastaError) -> Self {
        match err {
            CheckFastaError::InvalidInput(err) => {
                let error = &err.error;
                let additional_info = if let ParseError(BadNucleotide(_)) = error {
                    format!("Error parsing FASTA: {error}\n\n{BAD_NUCLEOTIDE_HINT}")
                } else {
                    format!("Error parsing FASTA: {error}")
                }.into();
                ApiError::InvalidInput(Fields {
                    additional_info,
                    line_number_range: Some((err.line_number as u64, err.line_number as u64)),
                })
            },
            CheckFastaError::EmptyFastaSequence(id) => ApiError::InvalidInput(Fields::new(format!("No sequences were specified in record {id}."))),
            CheckFastaError::WindowError(err) => ApiError::InternalServerError(Fields::new(format!("Unexpected response from internal server (hdb): {err}"))),
            CheckFastaError::DoprfError(err) => match err {
                DoprfError::HttpError(ref err @ HttpError::RequestError { status: Some(status), .. }) if status == 413 || status == 429 => {
                    // we return 413 for SCEP ratelimit overages as a non-retriable too many requests
                    ApiError::TooManyRequests(Fields::new(if status == 413 {
                        format!("certificate daily ratelimit exceeded: {err}")
                    } else {
                        err.to_string()
                    }))
                }
                err => ApiError::InternalServerError(Fields::new(format!("Unexpected error while processing sequences: {err}")))
            },
            CheckFastaError::RequestSizeTooBig(request_size, max_request_size) => ApiError::RequestTooBig(Fields::new(format!("Request of {request_size}bp exceeds configured limit of {max_request_size}bp."))),
            CheckFastaError::TemporaryMemoryLimitsReached(request_size, _max_system_size) => {
                ApiError::InternalServerError(Fields::new(format!("Request of {request_size}bp exceeds current system memory capacity. Please try again later.")))
            }
        }
    }
}

impl From<NcbiError> for ApiError {
    fn from(err: NcbiError) -> Self {
        match err {
            NcbiError::RequestFailed(err) => ApiError::InternalServerError(Fields::new(format!(
                "Couldn't reach the NCBI API: {err}"
            ))),
            NcbiError::RequestFailedWithStatus(status, err) => ApiError::InternalServerError(
                Fields::new(format!("NCBI returned unsuccessfully ({status}): {err}")),
            ),
            NcbiError::InvalidAccession(acc) => {
                ApiError::InvalidInput(Fields::new(format!("Accession number {acc} is invalid.")))
            }
        }
    }
}

#[cfg(feature = "native")]
impl From<crate::recaptcha::RecaptchaError> for ApiError {
    fn from(value: crate::recaptcha::RecaptchaError) -> Self {
        use crate::recaptcha::RecaptchaError;
        match value {
            RecaptchaError::DemoDisabled => {
                Self::Unauthorized(Fields::new("Demo is disabled for this server."))
            }
            RecaptchaError::Unreachable(err) => Self::InternalServerError(Fields::new(format!(
                "Could not reach reCAPTCHA endpoint: {err}"
            ))),
            RecaptchaError::Unparseable(err) => Self::InternalServerError(Fields::new(format!(
                "Got unexpected resposne from reCAPTCHA endpoint: {err}"
            ))),
            RecaptchaError::Unauthorized => {
                Self::Unauthorized(Fields::new("CAPTCHA was incorrect."))
            }
        }
    }
}

impl From<RateLimitExceeded> for ApiError {
    fn from(value: RateLimitExceeded) -> Self {
        let RateLimitExceeded { limit, unit } = value;
        ApiError::TooManyRequests(Fields::new(format!(
            "Maximum of {limit} requests allowed per {unit}."
        )))
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::InvalidInput(Fields::new(format!("Couldn't parse request: {err}")))
    }
}

impl<R: Role> From<TokenBundleError<R>> for ApiError {
    fn from(error: TokenBundleError<R>) -> Self {
        ApiError::InvalidInput(Fields::new(format!("Couldn't parse token: {error}")))
    }
}

impl From<InvalidClientTokenBundle<Exemption>> for ApiError {
    fn from(error: InvalidClientTokenBundle<Exemption>) -> Self {
        ApiError::InvalidInput(Fields::new(error.to_string()))
    }
}

impl From<UnusableRequestId> for ApiError {
    fn from(error: UnusableRequestId) -> Self {
        ApiError::InternalServerError(Fields::new(error.to_string()))
    }
}
