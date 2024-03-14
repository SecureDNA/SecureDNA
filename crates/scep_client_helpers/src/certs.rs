// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{borrow::Cow, path::Path};

use anyhow::Context;
use once_cell::sync::OnceCell;

use certificates::{
    file::{load_keypair_from_file, load_token_bundle_from_file},
    Certificate, Infrastructure, KeyPair, KeyUnavailable, PemDecodable, PublicKey,
    SynthesizerTokenGroup, TokenBundle,
};

#[derive(Clone)]
pub struct ClientCerts {
    pub issuer_pks: Cow<'static, [PublicKey]>,
    pub token: TokenBundle<SynthesizerTokenGroup>,
    pub keypair: KeyPair,
}

impl ClientCerts {
    fn load(
        token_path: impl AsRef<Path>,
        keypair_path: impl AsRef<Path>,
        keypair_passphrase: &str,
        issuer_pks: Cow<'static, [PublicKey]>,
    ) -> anyhow::Result<Self> {
        let token = load_token_bundle_from_file(token_path.as_ref())
            .with_context(|| format!("reading token from {:?}", token_path.as_ref()))?;

        let keypair = load_keypair_from_file(keypair_path.as_ref(), keypair_passphrase)
            .with_context(|| format!("reading keypair from {:?}", keypair_path.as_ref()))?;

        Ok(Self {
            issuer_pks,
            token,
            keypair,
        })
    }

    fn load_from_contents(
        token_contents: impl AsRef<[u8]>,
        keypair_contents: impl AsRef<[u8]>,
        keypair_passphrase: &str,
        issuer_pks: Cow<'static, [PublicKey]>,
    ) -> anyhow::Result<Self> {
        let token = TokenBundle::from_file_contents(token_contents.as_ref())
            .with_context(|| "parsing token")?;

        let keypair = KeyPair::load_key(keypair_contents.as_ref(), keypair_passphrase)
            .with_context(|| "parsing keypair")?;

        Ok(Self {
            issuer_pks,
            token,
            keypair,
        })
    }

    /// Load client certs with baked-in production roots and the given token / keypair
    pub fn load_with_prod_roots(
        token_path: impl AsRef<Path>,
        keypair_path: impl AsRef<Path>,
        keypair_passphrase: &str,
    ) -> anyhow::Result<Self> {
        Self::load(
            token_path,
            keypair_path,
            keypair_passphrase,
            infrastructure_root_keys().into(),
        )
    }

    /// Load client certs with baked-in production roots and the given token / keypair contents
    pub fn load_from_contents_with_prod_roots(
        token_contents: impl AsRef<[u8]>,
        keypair_contents: impl AsRef<[u8]>,
        keypair_passphrase: &str,
    ) -> anyhow::Result<Self> {
        Self::load_from_contents(
            token_contents,
            keypair_contents,
            keypair_passphrase,
            infrastructure_root_keys().into(),
        )
    }

    /// Load client certs with baked-in TEST ONLY roots and the given token / keypair
    /// This is not #[cfg(test)] because it's useful for locally testing a real server
    pub fn load_with_test_roots(
        token_path: impl AsRef<Path>,
        keypair_path: impl AsRef<Path>,
        keypair_passphrase: &str,
    ) -> anyhow::Result<Self> {
        Self::load(
            token_path,
            keypair_path,
            keypair_passphrase,
            test_infrastructure_root_keys().into(),
        )
    }

    /// Load client certs with baked-in TEST ONLY roots and the given token / keypair contents
    /// This is not #[cfg(test)] because it's useful for locally testing a real server
    pub fn load_from_contents_with_test_roots(
        token_contents: impl AsRef<[u8]>,
        keypair_contents: impl AsRef<[u8]>,
        keypair_passphrase: &str,
    ) -> anyhow::Result<Self> {
        Self::load_from_contents(
            token_contents,
            keypair_contents,
            keypair_passphrase,
            test_infrastructure_root_keys().into(),
        )
    }

    /// Load client certs with everything set to test certs
    pub fn load_test_certs() -> Self {
        let token_str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/certs/synthesizer-token.st"
        ));
        let keypair_str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/certs/synthesizer-token.priv"
        ));

        Self {
            issuer_pks: test_infrastructure_root_keys().into(),
            token: TokenBundle::from_file_contents(token_str).unwrap(),
            keypair: KeyPair::load_key(keypair_str, "test").unwrap(),
        }
    }

    /// Provide your own roots, used in integration tests where we generate fresh certificates
    pub fn with_custom_roots(
        issuer_pks: Vec<PublicKey>,
        token: TokenBundle<SynthesizerTokenGroup>,
        keypair: KeyPair,
    ) -> Self {
        Self {
            issuer_pks: issuer_pks.into(),
            token,
            keypair,
        }
    }
}

/// Contains baked-in root certs, so we don't need to ship a directory to clients
fn infrastructure_root_keys() -> &'static [PublicKey] {
    const KEY_STRINGS: [&str; 1] = [r#"
-----BEGIN SECUREDNA INFRASTRUCTURE CERTIFICATE-----
MIIBjaCCAYkwggGFoIIBP6AHgAVST09UMYEOSU5GUkFTVFJVQ1RVUkWiggEioIGH
gAhTVUJKRUNUMYEQxXUVM36qFZMYl+eecU14UoIgCRc++mnopFSNuXgcYjs7ddMu
AsFbxyfl56vxEzT5ZemjRYAdU2VjdXJlRE5BLWluZnJhc3RydWN0dXJlLXJvb3SB
JGNhLWluZnJhc3RydWN0dXJlLXJvb3RAc2VjdXJlZG5hLm9yZ6QAoYGVgAdJU1NV
RVIxgRB4YJ36QTaKWeX+gnhT/ubyomeAIAkXPvpp6KRUjbl4HGI7O3XTLgLBW8cn
5eer8RM0+WXpgUNTZWN1cmVETkEtaW5mcmFzdHJ1Y3R1cmUtcm9vdCwgY2EtaW5m
cmFzdHJ1Y3R1cmUtcm9vdEBzZWN1cmVkbmEub3Jnow2ABGXFVpCBBQCLYqKQpACB
QGTXlRAQ6jjgpEA6Idj2AyiQ92GyNuMPLRI51/Dfzsvgh1Ig3bNlD1hsLBL+Fepj
xxTl0mzFl6wm56U+mbJ9Qgo=
-----END SECUREDNA INFRASTRUCTURE CERTIFICATE-----
        "#];

    static KEYS: OnceCell<[PublicKey; 1]> = OnceCell::new();
    KEYS.get_or_init(|| {
        KEY_STRINGS.map(|key_str| {
            let bytes = key_str.as_bytes();
            let cert = Certificate::<Infrastructure, KeyUnavailable>::from_pem(bytes).unwrap();
            *cert.public_key()
        })
    })
}

/// Contains baked-in test root certs from test/certs/infrastructure_roots
fn test_infrastructure_root_keys() -> &'static [PublicKey] {
    const KEY_DIR: include_dir::Dir<'static> =
        include_dir::include_dir!("test/certs/infrastructure_roots");

    static KEYS: OnceCell<Vec<PublicKey>> = OnceCell::new();
    KEYS.get_or_init(|| {
        KEY_DIR
            .files()
            .map(|f| {
                let bytes = f.contents();
                let cert = Certificate::<Infrastructure, KeyUnavailable>::from_pem(bytes).unwrap();
                *cert.public_key()
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_load_certs_with_root() {
        let certs_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/certs");
        let certs = ClientCerts::load_with_prod_roots(
            format!("{certs_dir}/synthesizer-token.st"),
            format!("{certs_dir}/synthesizer-token.priv"),
            "test",
        )
        .unwrap();
        assert!(certs.issuer_pks.len() > 0);
    }

    #[test]
    fn can_load_certs_with_test_root() {
        let certs_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/certs");
        let certs = ClientCerts::load_with_test_roots(
            format!("{certs_dir}/synthesizer-token.st"),
            format!("{certs_dir}/synthesizer-token.priv"),
            "test",
        )
        .unwrap();
        assert!(certs.issuer_pks.len() > 0);
    }

    #[test]
    fn can_load_test_certs() {
        let certs = ClientCerts::load_test_certs();
        assert!(certs.issuer_pks.len() > 0);
    }
}
