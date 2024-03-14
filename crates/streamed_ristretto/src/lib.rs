// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Overview
//!
//! The [`streamed_ristretto`](crate) crate contains helpers for reading/writing streamed
//! ristretto point messages over HTTP.
//!
//! Most code should rely on the `hyper`, `reqwest`, or `web_sys` modules to interact with
//! libraries of the same name; each of these is only available if the corresponding feature
//! enabled.
//!
//! The [`stream`] module is always available and provides a number of lower-level but
//! (mostly) framework-agnostic components that can be used to support other HTTP frameworks.
//!
//! At the lowest level is a private `utils` module, with stream adapters to somewhat efficiently
//! mitigate frame boundaries not matching ristretto boundaries, and provide buffering. If
//! this is sufficiently useful, it may eventually make sense to make it public.
//!
//! # Format
//!
//! The streaming ristrettos format is pretty much just the older queryset format, except
//! that messages are expected to make use of the `Content-Type` and `Content-Length` headers.
//! The `Content-Type` must be set by the sender and validated by the receiver to indicate the
//! purpose of the ristrettos (e.g. queries, partial hashes, completed hashes, etc).
//! [`HasContentType`] can be used to look up appropriate `Content-Type`s. The `Content-Length`
//! should be set (in bytes) when the number of ristrettos is known ahead of time (which is
//! expected to always be the case).
//!
//! The message body is just a contiguous array of compressed (32 byte) ristretto points.
//!
//! Mid-stream errors may be indicated by breaking the connection, and optionally replacing a
//! 32-byte ristretto point with a 32-byte error message beginning and ending with a `0xFF`
//! byte (the `0xFF` bytes prevent errors from being mistaken for valid ristrettos, because
//! compressed ristrettos always have bits 7 and 248 cleared). Currently, such error messages
//! are only intended for human consumption, to aid in debugging.
//!
//! # Design Tidbits
//!
//! Streaming is HTTP-compatible! In particular,
//! [RFC 9110 section 7.5](https://httpwg.org/specs/rfc9110.html#rfc.section.7.5) explicitly
//! allows servers to send (and finish) a response before the associated request has finished.
//!
//! Many stream adapter functions return named types instead of opaque types. This makes the
//! implementation a lot uglier and harder to follow due to needing to manually implement polling,
//! but it has the advantage that the returned type is `Send`/`Sync` whenever the adapted stream
//! is, making it more widely usable without requiring `Send`/`Sync` variants of each adapter.
//! This is particularly important because we were running into issues where HTTP-related parts
//! of the DOPRF client code needed to be `Send`/`Sync` when compiled normally, and
//! non-`Send`/`Sync` when compiled for WASM.
//!
//! Providing error messages inline feels... kludgey, and perhaps error-prone. It's tempting to
//! instead send errors via HTTP trailers, but those are only supported with chunked
//! `Transfer-Encodings`. In theory
//! [RFC 9112 section 6.1](https://www.rfc-editor.org/rfc/rfc9112#section-6.1) allows
//! `Content-Length` to be used with chunked `Transfer-Encoding` but that seems discouraged
//! and `hyper` doesn't support it. Given that we want to require clients to specify the
//! message size up-front, that seems to exclude trailers.

mod contenttype;
pub mod stream;
pub mod util;

#[cfg(feature = "hyper")]
pub mod hyper;

#[cfg(feature = "reqwest")]
pub mod reqwest;

#[cfg(feature = "web-sys")]
pub mod web_sys;

pub use contenttype::HasContentType;
