// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Write;

use crate::version::ClientVersion;
use crate::{
    cookie::SessionCookie,
    nonce::{ClientNonce, ServerNonce},
};
use certificates::{Signature, SynthesizerTokenGroup, TokenBundle, TokenGroup};

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

// SCEP v2 mutual auth (including the session cookie / server mutual auth)
pub mod v2 {
    use super::*;

    pub fn generate_server_mutual_auth<T: TokenGroup>(
        server_protocol_version_nonce: (u64, ServerNonce),
        client_protocol_version_nonce: (ClientVersion, ClientNonce),
        server_cert_chain: &TokenBundle<T>,
        client_cert_chain: &TokenBundle<SynthesizerTokenGroup>,
        session_cookie: SessionCookie,
    ) -> Result<MutualAuth, certificates::EncodeError> {
        generate_mutual_auth_helper(
            "server-mutauth",
            server_protocol_version_nonce,
            client_protocol_version_nonce,
            server_cert_chain,
            client_cert_chain,
            session_cookie,
            None,
        )
    }

    pub fn generate_client_mutual_auth<T: TokenGroup>(
        server_protocol_version_nonce: (u64, ServerNonce),
        client_protocol_version_nonce: (ClientVersion, ClientNonce),
        server_cert_chain: &TokenBundle<T>,
        client_cert_chain: &TokenBundle<SynthesizerTokenGroup>,
        session_cookie: SessionCookie,
        server_mutual_auth_sig: &Signature,
    ) -> Result<MutualAuth, certificates::EncodeError> {
        generate_mutual_auth_helper(
            "client-mutauth",
            server_protocol_version_nonce,
            client_protocol_version_nonce,
            server_cert_chain,
            client_cert_chain,
            session_cookie,
            Some(server_mutual_auth_sig),
        )
    }

    /// Generates a pipe-separated ASCII string, in the right order, and appends the given certificate bytes.
    /// `domain_separator` must be a valid SCEP domain separator.
    fn generate_mutual_auth_helper<T: TokenGroup>(
        domain_separator: &'static str,
        server_protocol_version_nonce: (u64, ServerNonce),
        client_protocol_version_nonce: (ClientVersion, ClientNonce),
        server_cert_chain: &TokenBundle<T>,
        client_cert_chain: &TokenBundle<SynthesizerTokenGroup>,
        session_cookie: SessionCookie,
        // The server's mutual auth signature, used for client mutual auth, to prevent MITM attacks if a legitimate server was ever compromised
        previous_signature: Option<&Signature>,
    ) -> Result<MutualAuth, certificates::EncodeError> {
        let (server_version, server_nonce) = server_protocol_version_nonce;
        let server_nonce_base64 = server_nonce.to_plain_base64();

        let (client_protocol_version, client_nonce) = client_protocol_version_nonce;
        let client_nonce_base64 = client_nonce.to_plain_base64();

        let server_cert_chain_base64 = crate::base64::encode(server_cert_chain.to_wire_format()?);
        let client_cert_chain_base64 = crate::base64::encode(client_cert_chain.to_wire_format()?);

        let session_cookie_base64 = crate::base64::encode(session_cookie.as_ref());

        let suffix = match previous_signature {
            Some(sig) => format!("|{}", crate::base64::encode(sig.as_ref())),
            None => "".to_owned(),
        };

        let to_sign = format!(
            "{domain_separator}|\
            {server_version}|{server_nonce_base64}|\
            {client_protocol_version}|{client_nonce_base64}|\
            {server_cert_chain_base64}|{client_cert_chain_base64}|\
            {session_cookie_base64}{suffix}",
        );
        assert!(to_sign.is_ascii());

        Ok(MutualAuth(to_sign.into_bytes()))
    }
}

// SCEP v1 mutual auth (not including the session cookie / server mutual auth)
pub mod v1 {
    use super::*;

    pub fn generate_server_mutual_auth<T: TokenGroup>(
        server_protocol_version_nonce: (u64, ServerNonce),
        client_protocol_version_nonce: (ClientVersion, ClientNonce),
        server_cert_chain: &TokenBundle<T>,
    ) -> Result<MutualAuth, certificates::EncodeError> {
        generate_mutual_auth_helper(
            "server-mutauth",
            server_protocol_version_nonce,
            client_protocol_version_nonce,
            server_cert_chain,
        )
    }

    pub fn generate_client_mutual_auth(
        server_protocol_version_nonce: (u64, ServerNonce),
        client_protocol_version_nonce: (ClientVersion, ClientNonce),
        client_cert_chain: &TokenBundle<SynthesizerTokenGroup>,
    ) -> Result<MutualAuth, certificates::EncodeError> {
        generate_mutual_auth_helper(
            "client-mutauth",
            server_protocol_version_nonce,
            client_protocol_version_nonce,
            client_cert_chain,
        )
    }

    /// Generates a pipe-separated ASCII string, in the right order, and appends the given certificate bytes.
    /// `domain_separator` must be a valid SCEP domain separator.
    fn generate_mutual_auth_helper<T: TokenGroup>(
        domain_separator: &'static str,
        server_protocol_version_nonce: (u64, ServerNonce),
        client_protocol_version_nonce: (ClientVersion, ClientNonce),
        cert_chain: &TokenBundle<T>,
    ) -> Result<MutualAuth, certificates::EncodeError> {
        let cert_chain_bytes = cert_chain.to_wire_format()?;
        let (server_version, server_nonce) = server_protocol_version_nonce;
        let server_nonce_base64 = server_nonce.to_plain_base64();

        let (client_protocol_version, client_nonce) = client_protocol_version_nonce;
        let client_nonce_base64 = client_nonce.to_plain_base64();

        let to_sign = format!(
            "{domain_separator}|{server_version}|{server_nonce_base64}|{client_protocol_version}|{client_nonce_base64}|"
        );
        assert!(to_sign.is_ascii());

        let mut to_sign = to_sign.into_bytes();
        to_sign.extend(cert_chain_bytes);
        Ok(MutualAuth(to_sign))
    }
}
