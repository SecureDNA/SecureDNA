// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::{PrivateKeyInfo, SecretDocument};
use rand::rngs::OsRng;

use crate::key::error::{KeyDecryptionError, KeyEncryptionError};

use super::error::KeyIntoPkcs8Error;

// Password based encryption using scrypt as the password-based key derivation function and AES-256-CBC as the symmetric cipher.
pub fn encrypt_with_passphrase<B: AsRef<[u8]>>(
    doc: SecretDocument,
    passphrase: B,
) -> Result<SecretDocument, KeyEncryptionError> {
    let pki =
        PrivateKeyInfo::try_from(doc.as_bytes()).map_err(|_| KeyIntoPkcs8Error::Asn1Encode)?;

    let encrypted_doc = pki
        .encrypt(OsRng, passphrase)
        .map_err(|_| KeyEncryptionError::Encrypt)?;
    Ok(encrypted_doc)
}

// Compatible with both PBKDF2-SHA256 and scrypt key derivation functions.
pub fn decrypt_with_passphrase<B: AsRef<[u8]>>(
    bytes: &[u8],
    passphrase: B,
) -> Result<SecretDocument, KeyDecryptionError> {
    let encrypted_pki = EncryptedPrivateKeyInfo::try_from(bytes)
        .map_err(|err| KeyDecryptionError::ParseEncryptedPki(err.to_string()))?;
    let decrypted_pki = encrypted_pki
        .decrypt(passphrase)
        .map_err(|_| KeyDecryptionError::Decrypt)?;

    Ok(decrypted_pki)
}

#[cfg(all(test, feature = "cert_tests"))]
mod tests {
    use crate::key::{ecies::EciesKeyPair, EncryptableKeypair};

    use super::*;
    use pkcs8::pkcs5::pbes2;
    use rand::RngCore;

    // Password based encryption using PBKDF2-SHA256 with 100,000 iterations as the password-based key derivation function
    // and AES-256-CBC as the symmetric cipher.
    pub fn encrypt_with_passphrase_pbkdf2_sha256<B: AsRef<[u8]>>(
        doc: SecretDocument,
        passphrase: B,
    ) -> Result<SecretDocument, KeyEncryptionError> {
        let pki =
            PrivateKeyInfo::try_from(doc.as_bytes()).map_err(|_| KeyIntoPkcs8Error::Asn1Encode)?;

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        let pbes2_params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(100_000, &salt, &iv)
            .map_err(|_| KeyEncryptionError::InvalidParams)?;

        let encrypted_doc = pki
            .encrypt_with_params(pbes2_params, passphrase)
            .map_err(|_| KeyEncryptionError::Encrypt)?;

        Ok(encrypted_doc)
    }

    #[test]
    fn test_decrypt_scrypt() {
        let kp = EciesKeyPair::new_random();
        let passphrase = b"password";
        let encrypted = kp.to_encrypted(passphrase).unwrap();

        let result = decrypt_with_passphrase(encrypted.as_ref(), passphrase);
        assert!(
            result.is_ok(),
            "Failed to decrypt encrypted data using scrypt as the KDF"
        );
    }

    #[test]
    fn test_decrypt_pbkdf2_sha256() {
        let kp = EciesKeyPair::new_random();
        let passphrase = b"password";
        let pkcs8_der = kp.to_pkcs8_der().unwrap();
        let encrypted_doc = encrypt_with_passphrase_pbkdf2_sha256(pkcs8_der, passphrase).unwrap();

        let result = decrypt_with_passphrase(encrypted_doc.as_bytes(), passphrase);
        assert!(
            result.is_ok(),
            "Failed to decrypt encrypted data using PBKDF2-SHA256 as the KDF"
        );
    }
}
