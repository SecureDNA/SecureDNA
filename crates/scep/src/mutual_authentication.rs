// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Write;

use crate::nonce::{ClientNonce, ServerNonce};
use certificates::{SynthesizerTokenGroup, TokenBundle, TokenGroup};

pub struct MutualAuth(Vec<u8>);

impl AsRef<[u8]> for MutualAuth {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for MutualAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // write escaped ascii str
        for &b in &self.0 {
            for c in std::ascii::escape_default(b) {
                f.write_char(c.into())?;
            }
        }
        Ok(())
    }
}

pub fn generate_server_mutual_auth<ServerTokenKind>(
    server_version_nonce: (u64, ServerNonce),
    client_protocol_version_nonce: (u64, ClientNonce),
    server_cert_chain: &TokenBundle<ServerTokenKind>,
) -> Result<MutualAuth, certificates::EncodeError>
where
    ServerTokenKind: TokenGroup,
{
    let cert_chain_der = server_cert_chain.to_wire_format()?;
    Ok(generate_mutual_auth_helper(
        "server-mutauth",
        server_version_nonce,
        client_protocol_version_nonce,
        &cert_chain_der,
    ))
}

pub fn generate_client_mutual_auth(
    server_version_nonce: (u64, ServerNonce),
    client_protocol_version_nonce: (u64, ClientNonce),
    client_cert_chain: &TokenBundle<SynthesizerTokenGroup>,
) -> Result<MutualAuth, certificates::EncodeError> {
    let cert_chain_der = client_cert_chain.to_wire_format()?;
    Ok(generate_mutual_auth_helper(
        "client-mutauth",
        server_version_nonce,
        client_protocol_version_nonce,
        &cert_chain_der,
    ))
}

/// Generates a pipe-separated ASCII string, in the right order, and appends the given certificate bytes.
/// `domain_separator` must be a valid SCEP domain separator.
fn generate_mutual_auth_helper(
    domain_separator: &'static str,
    server_version_nonce: (u64, ServerNonce),
    client_protocol_version_nonce: (u64, ClientNonce),
    cert_chain_bytes: &[u8],
) -> MutualAuth {
    let (server_version, server_nonce) = server_version_nonce;
    let server_nonce_base64 = server_nonce.to_plain_base64();

    let (client_protocol_version, client_nonce) = client_protocol_version_nonce;
    let client_nonce_base64 = client_nonce.to_plain_base64();

    let to_sign = format!(
        "{domain_separator}|{server_version}|{server_nonce_base64}|{client_protocol_version}|{client_nonce_base64}|"
    );
    assert!(to_sign.is_ascii());

    let mut to_sign = to_sign.into_bytes();
    to_sign.extend(cert_chain_bytes);
    MutualAuth(to_sign)
}
