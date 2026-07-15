// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Write;

use crate::key::error::{KeyDecryptionError, KeyEncryptionError};
use crate::key::pbe;
use crate::pem::{PemDecodable, PemEncodable};
use crate::{KeyLoadError, KeyWriteError};

use super::error::{KeyFromPkcs8Error, KeyIntoPkcs8Error};

/// A trait for keypairs which can be serialized securely, using a password based encryption scheme.
pub trait EncryptableKeypair: Sized {
    type EncryptedKeyPair: AsRef<[u8]> + From<pkcs8::SecretDocument> + PemEncodable + PemDecodable;

    fn to_pkcs8_der(&self) -> Result<pkcs8::SecretDocument, KeyIntoPkcs8Error>;
    fn from_pkcs8_der<T: AsRef<[u8]>>(der: T) -> Result<Self, KeyFromPkcs8Error>;

    fn write_key<W: Write, T: AsRef<[u8]>>(
        &self,
        writer: &mut W,
        passphrase: T,
    ) -> Result<(), KeyWriteError> {
        let pem = self.to_encrypted(passphrase)?.to_pem()?;
        write!(writer, "{}", pem)?;
        Ok(())
    }

    fn load_key(pem: impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Self, KeyLoadError> {
        let encrypted = Self::EncryptedKeyPair::from_pem(pem)?;
        let keypair = Self::from_encrypted(encrypted, passphrase)?;
        Ok(keypair)
    }

    fn to_encrypted<B: AsRef<[u8]>>(
        &self,
        passphrase: B,
    ) -> Result<Self::EncryptedKeyPair, KeyEncryptionError> {
        let der = self.to_pkcs8_der()?;
        let encrypted_doc = pbe::encrypt_with_passphrase(der, passphrase)?;

        Ok(Self::EncryptedKeyPair::from(encrypted_doc))
    }

    fn from_encrypted<T: AsRef<[u8]>>(
        encrypted: Self::EncryptedKeyPair,
        passphrase: T,
    ) -> Result<Self, KeyDecryptionError> {
        let decrypted_doc = pbe::decrypt_with_passphrase(encrypted.as_ref(), passphrase)?;
        let keypair = Self::from_pkcs8_der(decrypted_doc.as_bytes())?;
        Ok(keypair)
    }
}
