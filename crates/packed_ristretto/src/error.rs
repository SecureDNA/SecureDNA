// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum DeserializeError {
    #[error("unknown format version {0}, expected {1}")]
    InvalidVersion(u8, u8),
    #[error("buffer size {0} is invalid")]
    InvalidSize(usize),
    #[error("magic {0:?} does not match expected magic {1:?}")]
    WrongMagic([u8; 4], [u8; 4]),
    #[error("length field {0} * 32 does not match actual size {1}")]
    WrongLength(u32, usize),
    #[error("checksums don't match: {0:#x} != {1:#x}")]
    WrongChecksum(u32, u32),
}
