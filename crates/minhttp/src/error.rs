// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Workaround for lack of `Box<dyn std::error::Error>: std::error::Error` implementation.
///
/// This type is a thin wrapper for `Box<dyn std::error::Error + Send + Sync>` that
/// implements [`std::error::Error`] and can have [`anyhow::Error`] be converted into it.
///
/// It's difficult to use [`anyhow::Error`] in callbacks that are expected to return
/// `Result<T, impl std::error::Error>`, because quite surprisingly [`anyhow::Error`]
/// does _not_ implement [`std::error::Error`]. The next obvious thing to do would be to
/// rely on the ability to convert [`anyhow::Error`] into [`Box<dyn std::error::Error>`]
/// but it turns out that doesn't implement [`std::error::Error`] either. This lack of
/// [`std::error::Error`] implementations ultimately stem from Rust's coherence rules
/// and the inability to use specialization. For a detailed explanation, check out
/// [this stack overflow question](https://stackoverflow.com/questions/65151237/why-doesnt-boxdyn-error-implement-error).
pub struct ErrWrapper(pub Box<dyn std::error::Error + Send + Sync>);

impl std::error::Error for ErrWrapper {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl std::fmt::Debug for ErrWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Display for ErrWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ErrWrapper {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self(err)
    }
}

impl From<anyhow::Error> for ErrWrapper {
    fn from(err: anyhow::Error) -> Self {
        Self(err.into())
    }
}
