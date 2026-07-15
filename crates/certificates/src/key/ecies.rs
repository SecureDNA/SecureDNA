// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};

use pkcs8::{
    ObjectIdentifier, PrivateKeyInfo, SecretDocument, der::zeroize::ZeroizeOnDrop,
    spki::AlgorithmIdentifier,
};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

use crate::{
    DecodeError, EncodeError, PemDecodable, PemEncodable,
    asn::{FromASN1DerBytes, ToASN1DerBytes},
    asn_encode_as_octet_string_impl,
    pem::PemTaggable,
};

use super::{
    EncryptableKeypair,
    error::{KeyFromPkcs8Error, KeyIntoPkcs8Error},
};

/// <http://oid-info.com/get/1.3.132.0.10>
pub const SECP256K1_ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

pub const SECP256K1_PRIV_KEY_LEN: usize = 32;

/// A secp256k1 keypair for use with the Elliptic Curve Integrated Encryption Scheme (ECIES).
/// The private key allows for decryption of messages which have been encrypted using the corresponding public key.
#[derive(Clone)]
pub struct EciesKeyPair(ecies::SecretKey, ecies::PublicKey);

impl EciesKeyPair {
    pub fn new_random() -> Self {
        let (sk, pk) = ecies::utils::generate_keypair();
        Self(sk, pk)
    }

    pub fn public_key(&self) -> EciesPublicKey {
        EciesPublicKey(self.1.serialize_compressed())
    }

    pub fn decrypt<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, EciesDecryptionError> {
        ecies::decrypt(&self.0.serialize(), message.as_ref())
            .map_err(|err| EciesDecryptionError(err.to_string()))
    }
}

impl EncryptableKeypair for EciesKeyPair {
    type EncryptedKeyPair = EciesEncryptedKeyPair;

    fn to_pkcs8_der(&self) -> Result<SecretDocument, KeyIntoPkcs8Error> {
        let mut private_key = [0u8; 2 + SECP256K1_PRIV_KEY_LEN];

        // Secp256k1 PKCS#8 keys are represented as a nested ASN.1 OCTET STRING
        // We need to add the inner tag here; the outer tag is added via `SecretDocument::encode_msg`
        private_key[0] = 0x04; // OCTET STRING tag
        private_key[1] = 0x20; // 32-byte length
        private_key[2..].copy_from_slice(&self.0.serialize());

        let public_key = self.1.serialize();

        let private_key_info = PrivateKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: SECP256K1_ALGORITHM_OID,
                parameters: None,
            },
            private_key: &private_key,
            public_key: Some(&public_key),
        };

        let result = SecretDocument::encode_msg(&private_key_info)
            .map_err(|_| KeyIntoPkcs8Error::Asn1Encode)?;
        Ok(result)
    }

    fn from_pkcs8_der<T: AsRef<[u8]>>(der: T) -> Result<Self, KeyFromPkcs8Error> {
        let pki = PrivateKeyInfo::try_from(der.as_ref())
            .map_err(|err| KeyFromPkcs8Error::Asn1Parse(err.to_string()))?;
        pki.algorithm
            .assert_algorithm_oid(SECP256K1_ALGORITHM_OID)
            .map_err(|_| KeyFromPkcs8Error::UnexpectedOid)?;

        if pki.algorithm.parameters.is_some() {
            return Err(KeyFromPkcs8Error::UnexpectedParams);
        }

        // Secp256k1 PKCS#8 keys are represented as a nested ASN.1 OCTET STRING
        let secret_key = match pki.private_key {
            [0x04, 0x20, rest @ ..] => rest,
            _ => return Err(KeyFromPkcs8Error::KeyBytesParse),
        };

        let public_key = pki.public_key.ok_or(KeyFromPkcs8Error::NoPublicKey)?;

        let sk = ecies::SecretKey::parse_slice(secret_key)
            .map_err(|_| KeyFromPkcs8Error::KeyBytesParse)?;
        let pk = ecies::PublicKey::parse_slice(public_key, None)
            .map_err(|_| KeyFromPkcs8Error::KeyBytesParse)?;
        Ok(Self(sk, pk))
    }
}

/// A public key for use with the Elliptic Curve Integrated Encryption Scheme (ECIES).
/// This key enables the encryption of messages intended exclusively for a recipient holding the corresponding private key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr)]
pub struct EciesPublicKey([u8; Self::LEN]);

impl EciesPublicKey {
    const LEN: usize = 33;

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

impl PemTaggable for EciesPublicKey {
    fn tag() -> String {
        "SECUREDNA AUDIT PUBLIC KEY".to_string()
    }
}

asn_encode_as_octet_string_impl!(EciesPublicKey, EciesPublicKey::LEN);

impl Display for EciesPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for EciesPublicKey {
    type Err = EciesPublicKeyParseError;

    /// Expects a hex encoded secp256k1 public key
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = hex::decode(s)
            .map_err(|_| EciesPublicKeyParseError)?
            .try_into()
            .map_err(|_| EciesPublicKeyParseError)?;
        Ok(Self(x))
    }
}

impl Debug for EciesPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secp256k1PublicKey")
            .field(&self.to_string())
            .finish()
    }
}

/// Pkcs8 encoded encrypted private key
pub struct EciesEncryptedKeyPair(SecretDocument);

impl From<SecretDocument> for EciesEncryptedKeyPair {
    fn from(doc: SecretDocument) -> Self {
        EciesEncryptedKeyPair(doc)
    }
}

impl AsRef<[u8]> for EciesEncryptedKeyPair {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl ZeroizeOnDrop for EciesEncryptedKeyPair {}

impl ToASN1DerBytes for EciesEncryptedKeyPair {
    fn to_der(&self) -> Result<Vec<u8>, EncodeError> {
        Ok(self.0.as_bytes().into())
    }
}

impl FromASN1DerBytes for EciesEncryptedKeyPair {
    fn from_der<B: AsRef<[u8]>>(data: B) -> Result<Self, DecodeError> {
        let doc = SecretDocument::try_from(data.as_ref()).map_err(|_| DecodeError::ParseError)?;
        Ok(Self(doc))
    }
}

impl PemTaggable for EciesEncryptedKeyPair {
    fn tag() -> String {
        "SECUREDNA ENCRYPTED AUDIT PRIVATE KEY".to_string()
    }
}

#[derive(Error, Debug)]
#[error("encryption key could not be parsed")]
pub struct EciesPublicKeyParseError;

pub fn encrypt_for_recipient(
    recipient_pk: &EciesPublicKey,
    message: &[u8],
) -> Result<Vec<u8>, EciesEncryptionError> {
    ecies::encrypt(&recipient_pk.0, message).map_err(|err| EciesEncryptionError(err.to_string()))
}

#[derive(Error, Debug)]
#[error("encryption failed: {0}")]
pub struct EciesEncryptionError(String);

#[derive(Error, Debug)]
#[error("decryption failed: {0}")]
pub struct EciesDecryptionError(String);

#[cfg(all(test, feature = "cert_tests"))]
mod tests {
    use std::str::FromStr;

    use crate::{
        EciesPublicKey,
        key::{
            EncryptableKeypair,
            ecies::{EciesKeyPair, encrypt_for_recipient},
        },
    };

    #[test]
    fn can_parse_ecies_public_key() {
        let (_, pk) = ecies::utils::generate_keypair();
        let hex = hex::encode(pk.serialize_compressed());
        EciesPublicKey::from_str(&hex).unwrap();
    }

    #[test]
    fn can_encrypt_and_decrypt() {
        let kp = EciesKeyPair::new_random();
        let message = b"test message";
        let encrypted_message = encrypt_for_recipient(&kp.public_key(), message).unwrap();
        let decrypted_message = kp.decrypt(encrypted_message).unwrap();
        assert_eq!(message.to_vec(), decrypted_message);
    }

    #[test]
    fn can_pkcs8_encode_and_decode() {
        let kp = EciesKeyPair::new_random();
        let encoded = kp.to_pkcs8_der().unwrap();
        let decoded = EciesKeyPair::from_pkcs8_der(encoded.as_bytes()).unwrap();
        assert_eq!(kp.0.serialize(), decoded.0.serialize());
    }
    #[test]
    fn can_encrypt_and_decrypt_with_passphrase() {
        let kp = EciesKeyPair::new_random();
        let passphrase = b"password";
        let encrypted_key = kp.to_encrypted(passphrase).unwrap();
        let decrypted_key = EciesKeyPair::from_encrypted(encrypted_key, passphrase).unwrap();
        assert_eq!(kp.0.serialize(), decrypted_key.0.serialize());
        assert_eq!(kp.1.serialize(), decrypted_key.1.serialize());
    }
}
