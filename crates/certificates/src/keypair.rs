// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use ed25519_dalek::SigningKey;
use std::fmt;
use std::fmt::{Debug, Display};
use std::io::Write;
use std::str::FromStr;

use ed25519::KeypairBytes;
use ed25519_dalek::Signature as Ed25519Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::VerifyingKey;
use pkcs8::der::zeroize::Zeroize;
use pkcs8::der::zeroize::ZeroizeOnDrop;
use pkcs8::pkcs5::pbes2;
use pkcs8::DecodePrivateKey;
use pkcs8::EncodePrivateKey;
use pkcs8::PrivateKeyInfo;
use pkcs8::SecretDocument;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_with::DeserializeFromStr;
use serde_with::SerializeDisplay;
use thiserror::Error;

use crate::asn::FromASN1DerBytes;
use crate::asn::ToASN1DerBytes;
use crate::asn_encode_as_octet_string_impl;
use crate::error::DecodeError;
use crate::error::EncodeError;
use crate::pem::PemDecodable;
use crate::pem::PemTaggable;
use crate::shared_components::common::Signed;
use crate::PemEncodable;

#[derive(Clone)]
pub struct KeyPair(SigningKey);
impl KeyPair {
    pub fn new_random() -> Self {
        let mut rng = OsRng;
        let keypair = SigningKey::generate(&mut rng);
        KeyPair(keypair)
    }

    pub fn public_key(&self) -> PublicKey {
        let inner: [u8; 32] = self.0.verifying_key().to_bytes();
        PublicKey(inner)
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.0.sign(message);
        let bytes: [u8; 64] = sig.to_bytes();
        Signature(bytes)
    }

    pub fn sign_asn_encodable_data<H: ToASN1DerBytes>(
        &self,
        data: H,
    ) -> Result<Signed<H>, EncodeError> {
        let bytes = data.to_der()?;
        let signature = self.sign(&bytes);
        Ok(Signed { data, signature })
    }

    pub fn write_key<W: Write, T: AsRef<[u8]>>(
        self,
        writer: &mut W,
        passphrase: T,
    ) -> Result<(), KeyWriteError> {
        let pem = self.to_encrypted(passphrase)?.to_pem()?;
        write!(writer, "{}", pem)?;
        Ok(())
    }

    pub fn load_key(
        pem: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<Self, KeyLoadError> {
        let encrypted = EncryptedKeyPair::from_pem(pem)?;
        let keypair = Self::from_encrypted(encrypted, passphrase)?;
        Ok(keypair)
    }

    // Password based encryption using PBKDF2-SHA256 as the password-based key derivation function and AES-256-CBC as the symmetric cipher.
    // Number of iterations recommended in 2023 by OWASP is 600,000. Changing to 600,000 caused tests to become very slow, leaving as 100,000 for now.
    fn to_encrypted<B: AsRef<[u8]>>(
        &self,
        passphrase: B,
    ) -> Result<EncryptedKeyPair, KeyEncryptionError> {
        let der = self.to_pkcs8_der().map_err(|_| KeyEncryptionError)?;
        let pki = PrivateKeyInfo::try_from(der.as_bytes()).map_err(|_| KeyEncryptionError)?;

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        let pbes2_params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(100_000, &salt, &iv)
            .map_err(|_| KeyEncryptionError)?;

        let encrypted_doc = pki
            .encrypt_with_params(pbes2_params, passphrase)
            .map_err(|_| KeyEncryptionError)?;

        Ok(EncryptedKeyPair(encrypted_doc))
    }

    fn from_encrypted<T: AsRef<[u8]>>(
        encrypted: EncryptedKeyPair,
        passphrase: T,
    ) -> Result<Self, KeyDecryptionError> {
        let bytes = KeypairBytes::from_pkcs8_encrypted_der(encrypted.0.as_bytes(), passphrase)
            .map_err(|_| KeyDecryptionError)?
            .to_bytes()
            .ok_or(KeyDecryptionError)?;

        let kp = SigningKey::from_keypair_bytes(&bytes).map_err(|_| KeyDecryptionError)?;
        Ok(Self(kp))
    }

    fn to_pkcs8_der(&self) -> Result<SecretDocument, EncodeError> {
        let mut bytes = self.0.to_keypair_bytes();
        let mut kpb = KeypairBytes::from_bytes(&bytes);
        let doc = kpb
            .to_pkcs8_der()
            .map_err(|err| EncodeError::AsnEncode(err.to_string()))?;
        kpb.secret_key.zeroize();
        bytes.zeroize();
        Ok(doc)
    }

    #[allow(dead_code)]
    fn from_pkcs8_der<T: AsRef<[u8]>>(der: T) -> Result<Self, DecodeError> {
        let mut kpb = KeypairBytes::from_pkcs8_der(der.as_ref())
            .map_err(|err| DecodeError::AsnDecode(err.to_string()))?;
        let mut bytes = kpb.to_bytes().ok_or(DecodeError::ParseError)?;
        let kp = SigningKey::from_keypair_bytes(&bytes).map_err(|_| DecodeError::ParseError)?;
        kpb.secret_key.zeroize();
        bytes.zeroize();
        Ok(KeyPair(kp))
    }
}

impl Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public key", &self.public_key())
            .field("private key", &"omitted for security")
            .finish()
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum KeyLoadError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Decrypt(#[from] KeyDecryptionError),
}

#[derive(Debug, Error, PartialEq)]
#[error("unable to encrypt key")]
pub struct KeyEncryptionError;
#[derive(Debug, Error, PartialEq)]
#[error("unable to decrypt key")]
pub struct KeyDecryptionError;

/// Pkcs8 encoded encrypted private key
pub struct EncryptedKeyPair(SecretDocument);
impl ZeroizeOnDrop for EncryptedKeyPair {}

impl PemTaggable for EncryptedKeyPair {
    fn tag() -> String {
        "SECUREDNA ENCRYPTED PRIVATE KEY".to_string()
    }
}

impl ToASN1DerBytes for EncryptedKeyPair {
    fn to_der(&self) -> Result<Vec<u8>, EncodeError> {
        Ok(self.0.as_bytes().into())
    }
}

impl FromASN1DerBytes for EncryptedKeyPair {
    fn from_der<B: AsRef<[u8]>>(data: B) -> Result<Self, DecodeError> {
        let doc = SecretDocument::try_from(data.as_ref()).map_err(|_| DecodeError::ParseError)?;
        Ok(Self(doc))
    }
}

#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
// tsgen
pub struct PublicKey([u8; Self::LEN]);

impl PublicKey {
    const LEN: usize = 32;

    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureVerificationError> {
        let pk = VerifyingKey::from_bytes(&self.0).map_err(|_| KeyParseError)?;
        let sig = Ed25519Signature::from_bytes(&signature.0);
        pk.verify_strict(message, &sig)
            .map_err(|_| SignatureVerificationError::NotVerifiedError)
    }
}

asn_encode_as_octet_string_impl!(PublicKey, PublicKey::LEN);

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for PublicKey {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = hex::decode(s)
            .map_err(|_| KeyParseError)?
            .try_into()
            .map_err(|_| KeyParseError)?;
        Ok(Self(x))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.to_string()).finish()
    }
}

impl PemTaggable for PublicKey {
    fn tag() -> String {
        "SECUREDNA PUBLIC KEY".to_string()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr)]
// tsgen
pub struct Signature([u8; Self::LEN]);

impl Signature {
    const LEN: usize = 64;
}

asn_encode_as_octet_string_impl!(Signature, Signature::LEN);

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Signature {
    type Err = SignatureParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = hex::decode(s)
            .map_err(|_| SignatureParseError)?
            .try_into()
            .map_err(|_| SignatureParseError)?;
        Ok(Self(x))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature").field(&self.to_string()).finish()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Error, Debug)]
pub enum SignatureVerificationError {
    /// Errors related to verifying signatures. Obscure by design, to not leak details about the signature or keys.
    #[error("unable to verify the signature")]
    NotVerifiedError,
    #[error(transparent)]
    KeyParseError(#[from] KeyParseError),
}

#[derive(Error, Debug)]
pub enum KeyWriteError {
    #[error("private key write error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Encrypt(#[from] KeyEncryptionError),
}

impl PartialEq for KeyWriteError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(err1), Self::Io(err2)) => err1.to_string() == err2.to_string(),
            (Self::Encode(l0), Self::Encode(r0)) => l0 == r0,
            (Self::Encrypt(l0), Self::Encrypt(r0)) => l0 == r0,
            _ => false,
        }
    }
}

#[derive(Error, Debug)]
#[error("key could not be parsed")]
pub struct KeyParseError;

#[derive(Error, Debug)]
#[error("signature could not be parsed")]
pub struct SignatureParseError;

#[cfg(test)]
mod tests {
    use crate::{
        keypair::{EncryptedKeyPair, KeyPair},
        pem::{PemDecodable, PemEncodable},
    };

    #[test]
    fn can_der_encode_private_key() {
        let kp = KeyPair::new_random();
        let encoded = kp.to_pkcs8_der().unwrap();
        let kp_decoded = KeyPair::from_pkcs8_der(encoded.as_bytes()).unwrap();
        assert_eq!(kp.0.to_bytes(), kp_decoded.0.to_bytes());
    }

    #[test]
    fn can_encrypt_and_decrypt_private_key() {
        let passphrase = "KuU7hZiUAVysd60";
        let kp = KeyPair::new_random();
        let encrypted = kp.to_encrypted(passphrase.as_bytes()).unwrap();
        let kp_decrypted = KeyPair::from_encrypted(encrypted, passphrase.as_bytes()).unwrap();
        assert_eq!(kp.0.to_bytes(), kp_decrypted.0.to_bytes());
    }

    #[test]
    fn decrypting_with_incorrect_passphrase_generates_error() {
        let passphrase = "KuU7hZiUAVysd60";
        let bad_passphrase = "bad_passphrase";

        let kp = KeyPair::new_random();
        let encrypted = kp.to_encrypted(passphrase.as_bytes()).unwrap();

        KeyPair::from_encrypted(encrypted, bad_passphrase.as_bytes())
            .expect_err("decrypting with incorrect passphrase should error");
    }

    #[test]
    fn can_pem_encode_and_decode_encrypted_key() {
        let passphrase = "KuU7hZiUAVysd60";

        let kp = KeyPair::new_random();
        let encrypted = kp.to_encrypted(passphrase.as_bytes()).unwrap();
        let encrypted_pem = encrypted.to_pem().unwrap();
        let encrypted = EncryptedKeyPair::from_pem(encrypted_pem).unwrap();
        let kp_decrypted = KeyPair::from_encrypted(encrypted, passphrase.as_bytes()).unwrap();
        assert_eq!(kp.0.to_bytes(), kp_decrypted.0.to_bytes());
    }

    #[test]
    fn can_write_keypair() {
        let passphrase = "KuU7hZiUAVysd60";

        let kp = KeyPair::new_random();
        let kp_bytes = kp.0.to_bytes();
        let mut key_backup = vec![];
        kp.write_key(&mut key_backup, passphrase).unwrap();

        let kp_decrypted = KeyPair::load_key(key_backup, passphrase.as_bytes()).unwrap();
        assert_eq!(kp_bytes, kp_decrypted.0.to_bytes());
    }
}
