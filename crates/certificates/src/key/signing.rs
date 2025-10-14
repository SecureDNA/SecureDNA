// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use ed25519_dalek::SigningKey;
use std::fmt;
use std::fmt::{Debug, Display};
use std::str::FromStr;

use ed25519::KeypairBytes;
use ed25519_dalek::Signature as Ed25519Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::VerifyingKey;
use pkcs8::der::zeroize::{Zeroize, ZeroizeOnDrop};
use pkcs8::DecodePrivateKey;
use pkcs8::EncodePrivateKey;
use pkcs8::SecretDocument;
use rand::rngs::OsRng;
use serde_with::DeserializeFromStr;
use serde_with::SerializeDisplay;

use crate::asn::{FromASN1DerBytes, ToASN1DerBytes};
use crate::asn_encode_as_octet_string_impl;
use crate::error::DecodeError;
use crate::error::EncodeError;
use crate::key::encryptable::EncryptableKeypair;
use crate::key::error::SignatureVerificationError;
use crate::pem::PemDecodable;
use crate::pem::PemTaggable;
use crate::shared_components::common::Signed;
use crate::PemEncodable;

use super::error::{KeyFromPkcs8Error, KeyIntoPkcs8Error, KeyParseError, SignatureParseError};

/// An ed25519 keypair for use with the EdDSA signature scheme.
#[derive(Clone)]
pub struct SigningKeyPair(SigningKey);
impl SigningKeyPair {
    pub fn new_random() -> Self {
        let mut rng = OsRng;
        let keypair = SigningKey::generate(&mut rng);
        SigningKeyPair(keypair)
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
}

impl EncryptableKeypair for SigningKeyPair {
    type EncryptedKeyPair = SigningEncryptedKeyPair;

    fn to_pkcs8_der(&self) -> Result<SecretDocument, KeyIntoPkcs8Error> {
        let mut bytes = self.0.to_keypair_bytes();
        let mut kpb = KeypairBytes::from_bytes(&bytes);
        let doc = kpb
            .to_pkcs8_der()
            .map_err(|_| KeyIntoPkcs8Error::Asn1Encode)?;
        kpb.secret_key.zeroize();
        bytes.zeroize();
        Ok(doc)
    }

    fn from_pkcs8_der<T: AsRef<[u8]>>(der: T) -> Result<Self, KeyFromPkcs8Error> {
        let mut kpb = KeypairBytes::from_pkcs8_der(der.as_ref())?;
        let mut bytes = kpb.to_bytes().ok_or(KeyFromPkcs8Error::KeyBytesParse)?;
        let kp =
            SigningKey::from_keypair_bytes(&bytes).map_err(|_| KeyFromPkcs8Error::KeyBytesParse)?;
        kpb.secret_key.zeroize();
        bytes.zeroize();
        Ok(SigningKeyPair(kp))
    }
}

impl Debug for SigningKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public key", &self.public_key())
            .field("private key", &"omitted for security")
            .finish()
    }
}

/// The public key allows for verification of signatures created using the corresponding private key.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
// tsgen
pub struct PublicKey(pub [u8; Self::LEN]);

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

    pub fn to_file_contents(&self) -> Result<String, EncodeError> {
        let pub_hex = self.to_string();
        let pem = self.to_pem()?;
        let contents = format!("{}\n{}", pub_hex, pem);
        Ok(contents)
    }

    pub fn from_file_contents(contents: impl AsRef<[u8]>) -> Result<Self, DecodeError> {
        Self::from_pem(contents)
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

/// Pkcs8 encoded encrypted private key
pub struct SigningEncryptedKeyPair(SecretDocument);

impl From<SecretDocument> for SigningEncryptedKeyPair {
    fn from(doc: SecretDocument) -> Self {
        SigningEncryptedKeyPair(doc)
    }
}

impl AsRef<[u8]> for SigningEncryptedKeyPair {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl ZeroizeOnDrop for SigningEncryptedKeyPair {}

impl ToASN1DerBytes for SigningEncryptedKeyPair {
    fn to_der(&self) -> Result<Vec<u8>, EncodeError> {
        Ok(self.0.as_bytes().into())
    }
}

impl FromASN1DerBytes for SigningEncryptedKeyPair {
    fn from_der<B: AsRef<[u8]>>(data: B) -> Result<Self, DecodeError> {
        let doc = SecretDocument::try_from(data.as_ref()).map_err(|_| DecodeError::ParseError)?;
        Ok(Self(doc))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr)]
// tsgen
pub struct Signature(pub [u8; Self::LEN]);

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

impl PemTaggable for SigningEncryptedKeyPair {
    fn tag() -> String {
        "SECUREDNA ENCRYPTED PRIVATE KEY".to_string()
    }
}

#[cfg(all(test, feature = "cert_tests"))]
mod tests {
    use crate::{
        key::{
            encryptable::EncryptableKeypair,
            signing::{SigningEncryptedKeyPair, SigningKeyPair},
        },
        pem::{PemDecodable, PemEncodable},
    };

    #[test]
    fn can_der_encode_private_key() {
        let kp = SigningKeyPair::new_random();
        let encoded = kp.to_pkcs8_der().unwrap();
        let kp_decoded = SigningKeyPair::from_pkcs8_der(encoded.as_bytes()).unwrap();
        assert_eq!(kp.0.to_bytes(), kp_decoded.0.to_bytes());
    }

    #[test]
    fn can_encrypt_and_decrypt_private_key() {
        let passphrase = "KuU7hZiUAVysd60";
        let kp = SigningKeyPair::new_random();
        let encrypted = kp.to_encrypted(passphrase.as_bytes()).unwrap();
        let kp_decrypted =
            SigningKeyPair::from_encrypted(encrypted, passphrase.as_bytes()).unwrap();
        assert_eq!(kp.0.to_bytes(), kp_decrypted.0.to_bytes());
    }

    #[test]
    fn decrypting_with_incorrect_passphrase_generates_error() {
        let passphrase = "KuU7hZiUAVysd60";
        let bad_passphrase = "bad_passphrase";

        let kp = SigningKeyPair::new_random();
        let encrypted = kp.to_encrypted(passphrase.as_bytes()).unwrap();

        SigningKeyPair::from_encrypted(encrypted, bad_passphrase.as_bytes())
            .expect_err("decrypting with incorrect passphrase should error");
    }

    #[test]
    fn can_pem_encode_and_decode_encrypted_key() {
        let passphrase = "KuU7hZiUAVysd60";

        let kp = SigningKeyPair::new_random();
        let encrypted = kp.to_encrypted(passphrase.as_bytes()).unwrap();
        let encrypted_pem = encrypted.to_pem().unwrap();
        let encrypted = SigningEncryptedKeyPair::from_pem(encrypted_pem).unwrap();
        let kp_decrypted =
            SigningKeyPair::from_encrypted(encrypted, passphrase.as_bytes()).unwrap();
        assert_eq!(kp.0.to_bytes(), kp_decrypted.0.to_bytes());
    }

    #[test]
    fn can_write_keypair() {
        let passphrase = "KuU7hZiUAVysd60";

        let kp = SigningKeyPair::new_random();
        let kp_bytes = kp.0.to_bytes();
        let mut key_backup = vec![];
        kp.write_key(&mut key_backup, passphrase).unwrap();

        let kp_decrypted = SigningKeyPair::load_key(key_backup, passphrase.as_bytes()).unwrap();
        assert_eq!(kp_bytes, kp_decrypted.0.to_bytes());
    }
}
