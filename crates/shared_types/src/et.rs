// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

/// An exemption token with an OTP that unlocks one of the requestor_auth_devices, and
/// possibly an OTP that unlocks one of the issuer_auth_devices if any are
/// present. The exemption token itself may be in PEM format (`T = String`) or decoded
/// (`T = TokenBundle<ExemptionTokenGroup>`).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Deserialize, Serialize)]
// tsgen
pub struct WithOtps<T> {
    pub et: T,

    /// Must match one of the requestor auth devices
    pub requestor_otp: String,

    /// If the exemption token has issuer auth devices, this OTP must be provided and match one of them.
    /// Otherwise, it is ignored.
    pub issuer_otp: Option<String>,
}

impl<T> WithOtps<T> {
    /// Convert `&WithOtps<T>` into `WithOtps<&T>` by cloning the OTPs.
    pub fn as_ref(&self) -> WithOtps<&T> {
        WithOtps {
            et: &self.et,
            requestor_otp: self.requestor_otp.clone(),
            issuer_otp: self.issuer_otp.clone(),
        }
    }

    pub fn try_map<U, E, F>(self, f: F) -> Result<WithOtps<U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        f(self.et).map(|u| WithOtps {
            et: u,
            requestor_otp: self.requestor_otp,
            issuer_otp: self.issuer_otp,
        })
    }
}
