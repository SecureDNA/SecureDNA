// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{self, Read};

use super::Metadata;
use doprf::prf::HashPart;

/// A single entry in a database file.
/// An entry is a block of `Entry::BYTE_LENGTH` bytes, the first part
/// (`Entry::HASH_LENGTH` bytes) being the `prf::HashPart`, and the second part
/// (`Entry::META_LENGTH`) being the `Metadata`.
/// Internally it is stored as just an array of bytes, so retrieving the `HashPart`
/// or `Metadata` requires a conversion, which is why those methods return a `Result`.

// think carefully before adding a serde Serialize/Deserialize impl for Entry!
// we need to avoid leaking entries in responses since they contain the secret hashes,
// and that will be easier to prevent doing accidentally if it's not possible to
// serialize or deserialize them to JSON
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub bytes: [u8; Self::BYTE_LENGTH],
}

impl Entry {
    pub const HASH_LENGTH: usize = 32;
    pub const META_LENGTH: usize = 8;
    pub const BYTE_LENGTH: usize = Self::HASH_LENGTH + Self::META_LENGTH;

    pub fn new(hash: HashPart, meta: Metadata) -> Self {
        let mut bytes = [0u8; Self::BYTE_LENGTH];

        let hash_bytes: [u8; 32] = (&hash).into();
        bytes[..32].copy_from_slice(&hash_bytes);

        let meta_bytes = u64::from(meta).to_le_bytes();
        bytes[32..].copy_from_slice(&meta_bytes);

        Self { bytes }
    }

    pub fn hash_slice(&self) -> &[u8] {
        &self.bytes[..Self::HASH_LENGTH]
    }

    pub fn hash_bytes(&self) -> [u8; Self::HASH_LENGTH] {
        // TODO: this won't require a copy when array::split_array_ref is stabilized
        let mut bytes = [0_u8; Self::HASH_LENGTH];
        bytes.copy_from_slice(self.hash_slice());
        bytes
    }

    /// Tries to convert the first `Self::HASH_LENGTH` bytes of this entry into
    /// a `HashPart`, returning an error if the conversion fails (see `HashPart`)
    pub fn hash_part(
        &self,
    ) -> Result<HashPart, <HashPart as TryFrom<&[u8; Self::HASH_LENGTH]>>::Error> {
        (&self.hash_bytes()).try_into()
    }

    pub fn metadata_slice(&self) -> &[u8] {
        &self.bytes[Self::HASH_LENGTH..]
    }

    pub fn metadata_bytes(&self) -> [u8; Self::META_LENGTH] {
        // TODO: this won't require a copy when array::split_array_ref is stabilized
        let mut bytes = [0_u8; Self::META_LENGTH];
        bytes.copy_from_slice(self.metadata_slice());
        bytes
    }

    /// Tries to convert the last `Self::META_LENGTH` bytes of this entry into
    /// a `Metadata`, returning an error if the conversion fails (see `Metadata`)
    pub fn metadata(&self) -> Result<Metadata, <Metadata as TryFrom<u64>>::Error> {
        u64::from_le_bytes(self.metadata_bytes()).try_into()
    }

    /// If EOF, returns Ok(true) and contents of buf should be ignored
    fn read_block<R: Read>(mut reader: R, mut buf: &mut [u8]) -> io::Result<bool> {
        let mut has_read = false;
        while !buf.is_empty() {
            match reader.read(buf) {
                Ok(0) => {
                    if !has_read {
                        // we haven't touched `buf`, and we read 0 so the previous call must have read the last block
                        return Ok(true);
                    } else if !buf.is_empty() {
                        // we've partially filled buf
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "failed to fill buffer",
                        ));
                    } else {
                        // we've walked buf to the end in the Ok(n) branch and it's filled
                        // this is probably the EOF but since we can't catch all cases in this branch, it's better for the
                        // caller to call again
                        return Ok(false);
                    }
                }
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    has_read = true;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if !buf.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
        } else {
            Ok(false)
        }
    }

    /// Read all Entry-sized blocks from the given reader
    /// Errors if the reader does not provide a Self::BYTE_LENGTH-multiple sized number
    /// of bytes
    pub fn read_all_from_reader<R: Read>(mut reader: R) -> io::Result<Vec<Self>> {
        let mut result = Vec::new();

        loop {
            let mut bytes = [0u8; Self::BYTE_LENGTH];
            if Self::read_block(&mut reader, &mut bytes)? {
                // end of file
                break;
            }

            result.push(Self { bytes });
        }

        Ok(result)
    }
}

impl From<[u8; Entry::BYTE_LENGTH]> for Entry {
    fn from(bytes: [u8; Entry::BYTE_LENGTH]) -> Self {
        Self { bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reader() {
        let fake_file = vec![0xab_u8; 40 * 9876];
        let reader = io::BufReader::new(&fake_file[..]);
        let result = Entry::read_all_from_reader(reader).unwrap();
        assert_eq!(result.len(), 9876);
    }

    #[test]
    fn test_reader_wrong_len() {
        let fake_file = vec![0xab_u8; 39 * 9876];
        let reader = io::BufReader::new(&fake_file[..]);
        Entry::read_all_from_reader(reader).unwrap_err();
    }
}
