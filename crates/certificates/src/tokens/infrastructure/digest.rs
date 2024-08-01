// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Display;

use doprf::party::KeyserverId;
use serde::Serialize;

use crate::shared_components::common::CompatibleIdentity;
use crate::shared_components::digest::{INDENT, INDENT2};
use crate::{
    DatabaseToken, DatabaseTokenRequest, Expiration, HltToken, HltTokenRequest, Id, KeyserverToken,
    KeyserverTokenRequest, PublicKey, Signature,
};

use super::database::{DatabaseTokenRequestVersion, DatabaseTokenVersion};
use super::hlt::{HltTokenRequestVersion, HltTokenVersion};
use super::keyserver::{KeyserverTokenRequestVersion, KeyserverTokenVersion};

#[derive(Serialize)]
pub struct DatabaseTokenRequestDigest {
    version: String,
    request_id: Id,
    public_key: PublicKey,
}

impl From<DatabaseTokenRequest> for DatabaseTokenRequestDigest {
    fn from(value: DatabaseTokenRequest) -> Self {
        match value.version {
            DatabaseTokenRequestVersion::V1(r) => {
                let version = "V1".to_string();
                let request_id = r.request_id;
                let public_key = r.public_key;
                DatabaseTokenRequestDigest {
                    version,
                    request_id,
                    public_key,
                }
            }
        }
    }
}

impl Display for DatabaseTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Database Token Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        write!(f, "{:INDENT2$}{}", "", self.public_key)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct DatabaseTokenDigest {
    version: String,
    request_id: Id,
    issuance_id: Id,
    public_key: PublicKey,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    signature: Signature,
}

impl<K> From<DatabaseToken<K>> for DatabaseTokenDigest {
    fn from(value: DatabaseToken<K>) -> Self {
        match value.version {
            DatabaseTokenVersion::V1(t) => {
                let version = "V1".to_string();
                let request_id = t.data.request.request_id;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let public_key = t.data.request.public_key;
                let expiration = t.data.issuer_fields.expiration;
                let signature = t.signature;
                let issued_by = t.data.issuer_fields.identity;
                DatabaseTokenDigest {
                    version,
                    request_id,
                    issuance_id,
                    public_key,
                    expiration,
                    signature,
                    issued_by,
                }
            }
        }
    }
}

impl Display for DatabaseTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Database Token", self.version)?;
        writeln!(f, "{:INDENT$}Issuance ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issuance_id)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Issued by:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issued_by)?;
        writeln!(f, "{}", self.expiration)?;
        writeln!(f, "{:INDENT$}Signature:", "")?;
        write!(f, "{:INDENT2$}{}", "", self.signature)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct HltTokenRequestDigest {
    version: String,
    request_id: Id,
    public_key: PublicKey,
}

impl From<HltTokenRequest> for HltTokenRequestDigest {
    fn from(value: HltTokenRequest) -> Self {
        match value.version {
            HltTokenRequestVersion::V1(r) => {
                let version = "V1".to_string();
                let request_id = r.request_id;
                let public_key = r.public_key;
                HltTokenRequestDigest {
                    version,
                    request_id,
                    public_key,
                }
            }
        }
    }
}

impl Display for HltTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} HLT Token Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        write!(f, "{:INDENT2$}{}", "", self.public_key)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct HltTokenDigest {
    version: String,
    request_id: Id,
    issuance_id: Id,
    public_key: PublicKey,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    signature: Signature,
}

impl<K> From<HltToken<K>> for HltTokenDigest {
    fn from(value: HltToken<K>) -> Self {
        match value.version {
            HltTokenVersion::V1(t) => {
                let version = "V1".to_string();
                let request_id = t.data.request.request_id;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let public_key = t.data.request.public_key;
                let expiration = t.data.issuer_fields.expiration;
                let signature = t.signature;
                let issued_by = t.data.issuer_fields.identity;

                HltTokenDigest {
                    version,
                    request_id,
                    issuance_id,
                    public_key,
                    expiration,
                    signature,
                    issued_by,
                }
            }
        }
    }
}

impl Display for HltTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} HLT Token", self.version)?;
        writeln!(f, "{:INDENT$}Issuance ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issuance_id)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Issued by:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issued_by)?;
        writeln!(f, "{}", self.expiration)?;
        writeln!(f, "{:INDENT$}Signature:", "")?;
        write!(f, "{:INDENT2$}{}", "", self.signature)?;

        Ok(())
    }
}

#[derive(Serialize)]
pub struct KeyserverTokenRequestDigest {
    version: String,
    keyserver_id: KeyserverId,
    request_id: Id,
    public_key: PublicKey,
}

impl From<KeyserverTokenRequest> for KeyserverTokenRequestDigest {
    fn from(value: KeyserverTokenRequest) -> Self {
        match value.version {
            KeyserverTokenRequestVersion::V1(r) => {
                let version = "V1".to_string();
                let keyserver_id = r.keyserver_id;
                let request_id = r.request_id;
                let public_key = r.public_key;
                KeyserverTokenRequestDigest {
                    version,
                    keyserver_id,
                    request_id,
                    public_key,
                }
            }
        }
    }
}

impl Display for KeyserverTokenRequestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Keyserver Token Request", self.version)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Keyserver ID:", "")?;
        write!(f, "{:INDENT2$}{}", "", self.keyserver_id)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct KeyserverTokenDigest {
    version: String,
    request_id: Id,
    issuance_id: Id,
    keyserver_id: KeyserverId,
    public_key: PublicKey,
    issued_by: CompatibleIdentity,
    expiration: Expiration,
    signature: Signature,
}

impl<K> From<KeyserverToken<K>> for KeyserverTokenDigest {
    fn from(value: KeyserverToken<K>) -> Self {
        match value.version {
            KeyserverTokenVersion::V1(t) => {
                let version = "V1".to_string();
                let request_id = t.data.request.request_id;
                let issuance_id = t.data.issuer_fields.issuance_id;
                let keyserver_id = t.data.request.keyserver_id;
                let public_key = t.data.request.public_key;
                let expiration = t.data.issuer_fields.expiration;
                let signature = t.signature;
                let issued_by = t.data.issuer_fields.identity;
                KeyserverTokenDigest {
                    version,
                    request_id,
                    issuance_id,
                    keyserver_id,
                    public_key,
                    expiration,
                    signature,
                    issued_by,
                }
            }
        }
    }
}

impl Display for KeyserverTokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} Keyserver Token", self.version)?;
        writeln!(f, "{:INDENT$}Issuance ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issuance_id)?;
        writeln!(f, "{:INDENT$}Request ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.request_id)?;
        writeln!(f, "{:INDENT$}Public Key:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.public_key)?;
        writeln!(f, "{:INDENT$}Keyserver ID:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.keyserver_id)?;
        writeln!(f, "{:INDENT$}Issued by:", "")?;
        writeln!(f, "{:INDENT2$}{}", "", self.issued_by)?;
        writeln!(f, "{}", self.expiration)?;
        writeln!(f, "{:INDENT$}Signature:", "")?;
        write!(f, "{:INDENT2$}{}", "", self.signature)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use doprf::party::KeyserverId;

    use crate::test_helpers::{
        expected_database_token_display, expected_hlt_token_display,
        expected_keyserver_token_display,
    };
    use crate::{
        test_helpers::create_leaf_cert, DatabaseTokenRequest, Digestible, Expiration,
        Infrastructure, Issued, KeyPair,
    };
    use crate::{HltTokenRequest, KeyserverTokenRequest};

    #[test]
    fn digest_display_for_database_token_matches_expected_display() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = DatabaseTokenRequest::v1_token_request(kp.public_key());

        let token = cert
            .issue_database_token(req, Expiration::default())
            .unwrap();
        let expected_text = expected_database_token_display(
            &token,
            &format!("(public key: {})", token.issuer_public_key()),
        );
        let text = token.into_digest().to_string();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn digest_display_for_hlt_token_matches_expected_display() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = HltTokenRequest::v1_token_request(kp.public_key());

        let token = cert.issue_hlt_token(req, Expiration::default()).unwrap();
        let expected_text = expected_hlt_token_display(
            &token,
            &format!("(public key: {})", token.issuer_public_key()),
        );
        let text = token.into_digest().to_string();
        assert_eq!(text, expected_text);
    }

    #[test]
    fn digest_display_for_keyserver_token_matches_expected_display() {
        let cert = create_leaf_cert::<Infrastructure>();
        let kp = KeyPair::new_random();
        let req = KeyserverTokenRequest::v1_token_request(
            kp.public_key(),
            KeyserverId::try_from(1).unwrap(),
        );

        let token = cert
            .issue_keyserver_token(req, Expiration::default())
            .unwrap();
        let expected_text = expected_keyserver_token_display(
            &token,
            "1",
            &format!("(public key: {})", token.issuer_public_key()),
        );
        let text = token.into_digest().to_string();
        assert_eq!(text, expected_text);
    }
}
