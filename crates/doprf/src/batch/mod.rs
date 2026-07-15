// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holds code related to splitting windows into evenly sized batches.
//!
//! Streaming needs to operate in batches. There are two main reasons for this:
//! * The keyserver verification code uses variable-time operations, so it needs to run in batches
//!   of at least ~100 hashes to obscure leaked timing information.
//! * If we want hashing to run as quickly as possible, we need to skip individual keyserver
//!   verification unless the overall results are invalid. However, that means we need to keep
//!   verification-related information around, lest we need to identify *which* keyserver was
//!   malicous. Batching limits how much memory that takes up.

pub mod iter;
pub mod layout;
