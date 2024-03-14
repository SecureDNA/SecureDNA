// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)] // Note: this is slightly different from std Instant (missing Eq, Ord, and Hash)
pub struct Instant {
    pub millis: f64,
}

#[cfg(target_arch = "wasm32")]
impl Instant {
    pub fn elapsed(&self) -> std::time::Duration {
        let millis = js_sys::Date::now() - self.millis;
        std::time::Duration::from_secs_f64(millis / 1e3)
    }
}

#[cfg(target_arch = "wasm32")]
impl std::ops::Add<std::time::Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: std::time::Duration) -> Self::Output {
        Self {
            millis: self.millis + rhs.as_secs_f64() * 1e3,
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub fn get_now() -> Instant {
    Instant {
        millis: js_sys::Date::now(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::disallowed_types)]
pub type Instant = std::time::Instant;

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::disallowed_types)]
pub fn get_now() -> std::time::Instant {
    std::time::Instant::now()
}
