// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Following the logic of the hyper-rustls server example:
// https://github.com/rustls/hyper-rustls/blob/main/examples/server.rs
// under MIT license OR Apache-2.0

use std::io::{self, Cursor, ErrorKind::InvalidData};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use futures::TryStreamExt;
use http::uri::{Authority, PathAndQuery, Scheme, Uri};
use hyper::header::{HeaderValue, HOST};
use hyper::{Request, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

use super::traits::{AppState, Listener, ReadFileFn, RelativeConfig, ResponseFn};
use crate::response::{temporary_redirect, text};

const STANDARD_TLS_PORT: u16 = 443;

/// TLS listening configuration
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TlsConfig {
    /// Address to listen on for incoming TLS connections.
    pub tls_address: SocketAddr,
    /// Path to TLS certificate in PEM format.
    pub tls_certificate: PathBuf,
    /// Path to TLS private key in PEM format.
    pub tls_private_key: PathBuf,
}

impl TlsConfig {
    /// Like `Option::<TlsConfig>::deserialize`, but only returns `None` if all fields are omitted.
    ///
    /// If any field of [`TlsConfig`] is given, then any missing required fields result in an error.
    pub(crate) fn deserialize_option<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Self>, D::Error> {
        // TlsConfig but where every field is optional
        #[derive(Debug, Deserialize)]
        struct OptionalSelf {
            pub tls_address: Option<SocketAddr>,
            pub tls_certificate: Option<PathBuf>,
            pub tls_private_key: Option<PathBuf>,
        }

        let OptionalSelf {
            tls_address,
            tls_certificate,
            tls_private_key,
        } = OptionalSelf::deserialize(deserializer)?;

        // Allow the TlsConfig to be genuinely omitted...
        if tls_address.is_none() && tls_certificate.is_none() && tls_private_key.is_none() {
            return Ok(None);
        }
        // ...but if any fields are specified, then missing fields are an error.
        Ok(Some(Self {
            tls_address: tls_address.ok_or_else(|| de::Error::missing_field("tls_address"))?,
            tls_certificate: tls_certificate
                .ok_or_else(|| de::Error::missing_field("tls_certificate"))?,
            tls_private_key: tls_private_key
                .ok_or_else(|| de::Error::missing_field("tls_private_key"))?,
        }))
    }
}

impl RelativeConfig for TlsConfig {
    fn relative_to(self, base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        Self {
            tls_certificate: base.join(self.tls_certificate),
            tls_private_key: base.join(self.tls_private_key),
            tls_address: self.tls_address,
        }
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
enum HttpsUriError {
    #[error("missing Host header")]
    MissingHostHeader,
    #[error("couldn't parse Host header")]
    InvalidHostHeader,
    // These two probably aren't reachable in practice, but they're included just in case...
    #[error("couldn't construct valid authority")]
    InvalidAuthority,
    #[error("couldn't construct valid URI")]
    InvalidUri,
}

impl HttpsUriError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingHostHeader | Self::InvalidHostHeader => StatusCode::BAD_REQUEST,
            Self::InvalidAuthority | Self::InvalidUri => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Sets up TLS and wraps the given [`Listener`] with a [`TlsAcceptor`]
pub async fn terminate_tls_to_listener(
    read_file: impl ReadFileFn,
    certs_path: &Path,
    private_key_path: &Path,
    listener: impl Listener,
) -> anyhow::Result<impl Listener> {
    let certs = load_certs(read_file.clone(), certs_path).await?;
    let key = load_private_key(read_file, private_key_path).await?;
    let tls_acceptor = setup_tls_acceptor(certs, key)?;
    Ok(apply_tls_acceptor(tls_acceptor, listener))
}

/// Load certs at `path` via `read_file`.
async fn load_certs(
    read_file: impl ReadFileFn,
    path: &Path,
) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs = read_file(path.to_owned())
        .await
        .with_context(|| format!("Couldn't open certificates at {}", path.display()))?;
    let certs: Result<_, _> = rustls_pemfile::certs(&mut Cursor::new(certs)).collect();
    certs.with_context(|| format!("Couldn't parse certificates at {}", path.display()))
}

/// Load a private key at `path` via `read_file`.
async fn load_private_key(
    read_file: impl ReadFileFn,
    path: &Path,
) -> anyhow::Result<PrivateKeyDer<'static>> {
    let key = read_file(path.to_owned())
        .await
        .with_context(|| format!("Couldn't open private key at {}", path.display()))?;
    rustls_pemfile::private_key(&mut Cursor::new(key))
        .transpose()
        .unwrap_or_else(|| Err(std::io::Error::new(InvalidData, "Empty private key")))
        .with_context(|| format!("Couldn't parse private key at {}", path.display()))
}

/// Build a [`TlsAcceptor`] configured to use a fixed cert/key.
fn setup_tls_acceptor(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> std::io::Result<TlsAcceptor> {
    // Note that ServerConfig means TLS config in this context.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::other(e.to_string()))?;
    server_config.alpn_protocols = vec![
        // We don't support HTTP 2 yet.
        // b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"http/1.0".to_vec(),
    ];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Applies the given [`TlsAcceptor`] to the given [`Listener`].
///
/// The given `tls_acceptor` will be used to accept all connections yielded by `listener`.
fn apply_tls_acceptor(tls_acceptor: TlsAcceptor, listener: impl Listener) -> impl Listener {
    move || {
        let tls_acceptor = tls_acceptor.clone();
        listener().and_then(move |(connection, socket_addr)| {
            let tls_acceptor = tls_acceptor.clone();
            async move { Ok((tls_acceptor.accept(connection).await?, socket_addr)) }
        })
    }
}

/// Attempts to redirect all requests to HTTPS on the specified `tls_port`.
pub fn redirect_to_https<AS: AppState>(tls_port: u16) -> impl ResponseFn<AS> {
    move |_state, _addr, request| {
        let https_uri = https_uri(tls_port, &request);
        async {
            let https_uri = match https_uri {
                Ok(uri) => uri.to_string(),
                Err(err) => {
                    return text(
                        err.status_code(),
                        format!("Can't build redirect URI: {err}."),
                    )
                }
            };
            match HeaderValue::try_from(https_uri.to_string()) {
                Ok(uri) => temporary_redirect(uri),
                // Probably not reachable...
                Err(_) => text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Redirect URI could not be encoded as header.",
                ),
            }
        }
    }
}

// Tries to infer what the request URI was and return an HTTPS version of it.
//
// Because HTTP 1.1 mandates Host headers, this should (hopefully) return Some(uri) for
// valid requests but it's hard to really be sure.
fn https_uri<T>(tls_port: u16, request: &Request<T>) -> Result<Uri, HttpsUriError> {
    let host = request
        .headers()
        .get(HOST)
        .ok_or(HttpsUriError::MissingHostHeader)?;

    // Strip off extra stuff like explicitly specified ports
    let host =
        Authority::try_from(host.as_bytes()).map_err(|_| HttpsUriError::InvalidHostHeader)?;
    let host = host.host();

    // TODO: maybe compare host of uri against host header in case somebody
    // submitted an absolute URI?

    let authority = if tls_port != STANDARD_TLS_PORT {
        &format!("{host}:{tls_port}")
    } else {
        host
    };
    let authority = Authority::try_from(authority).map_err(|_| HttpsUriError::InvalidAuthority)?;

    let mut uri_parts = request.uri().clone().into_parts();
    uri_parts.scheme = Some(Scheme::HTTPS);
    uri_parts.authority = Some(authority);
    if uri_parts.path_and_query.is_none() {
        // Prevent URI construction errors with pathological request URIs like example.com
        uri_parts.path_and_query = Some(PathAndQuery::from_static("/"));
    }
    Uri::try_from(uri_parts).map_err(|_| HttpsUriError::InvalidUri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct OuterConfig {
        some_field: u32,

        #[serde(flatten)]
        #[serde(deserialize_with = "TlsConfig::deserialize_option")]
        pub tls_config: Option<TlsConfig>,
    }

    #[test]
    fn redirect_handles_standard_ports() {
        let request = Request::builder()
            .header("Host", "foo.com")
            .body(())
            .unwrap();
        let uri = https_uri(443, &request).unwrap();
        assert_eq!(uri, "https://foo.com/");
    }

    #[test]
    fn redirect_handles_nonstandard_http_port() {
        let request = Request::builder()
            .header("Host", "foo.com:8080")
            .body(())
            .unwrap();
        let uri = https_uri(443, &request).unwrap();
        assert_eq!(uri, "https://foo.com/");
    }

    #[test]
    fn redirect_handles_nonstandard_https_port() {
        let request = Request::builder()
            .header("Host", "foo.com")
            .body(())
            .unwrap();
        let uri = https_uri(8081, &request).unwrap();
        assert_eq!(uri, "https://foo.com:8081/");
    }

    #[test]
    fn redirect_handles_nonstandard_ports() {
        let request = Request::builder()
            .header("Host", "foo.com:8080")
            .body(())
            .unwrap();
        let uri = https_uri(8081, &request).unwrap();
        assert_eq!(uri, "https://foo.com:8081/");
    }

    #[test]
    fn redirect_keeps_paths_intact() {
        let request = Request::builder()
            .uri("/this/is/a/path?and&a&query=123#frag")
            .header("Host", "foo.com:8080")
            .body(())
            .unwrap();
        let uri = https_uri(8081, &request).unwrap();
        assert_eq!(
            uri,
            "https://foo.com:8081/this/is/a/path?and&a&query=123#frag"
        );
    }

    #[test]
    fn redirect_handles_missing_path() {
        let request = Request::builder()
            .uri("foo.com")
            .header("Host", "foo.com")
            .body(())
            .unwrap();
        let uri = https_uri(8081, &request).unwrap();
        assert_eq!(uri, "https://foo.com:8081/");
    }

    #[test]
    fn redirect_rejects_missing_host_headers() {
        let request = Request::builder().body(()).unwrap();
        assert_eq!(
            https_uri(8081, &request),
            Err(HttpsUriError::MissingHostHeader)
        );
    }

    #[test]
    fn redirect_rejects_invalid_host_headers() {
        let request = Request::builder()
            .header("Host", "foo.com:8080:123")
            .body(())
            .unwrap();
        assert_eq!(
            https_uri(8081, &request),
            Err(HttpsUriError::InvalidHostHeader)
        );
    }

    #[test]
    fn accepts_completely_omitted_tls_configs() {
        let cfg = toml::from_str::<OuterConfig>("some_field = 123").unwrap();
        assert_eq!(
            cfg,
            OuterConfig {
                some_field: 123,
                tls_config: None
            }
        );
    }

    #[test]
    fn accepts_complete_tls_configs() {
        let cfg = r#"
            some_field = 123
            tls_address = "1.2.3.4:443"
            tls_certificate = "server.crt"
            tls_private_key = "server.key"
        "#;
        let cfg = toml::from_str::<OuterConfig>(cfg).unwrap();
        assert_eq!(
            cfg,
            OuterConfig {
                some_field: 123,
                tls_config: Some(TlsConfig {
                    tls_address: "1.2.3.4:443".parse().unwrap(),
                    tls_certificate: "server.crt".into(),
                    tls_private_key: "server.key".into(),
                })
            }
        );
    }

    #[test]
    fn rejects_incomplete_tls_configs() {
        let cfg = r#"
            some_field = 123
            tls_address = "1.2.3.4:443"
        "#;
        toml::from_str::<OuterConfig>(cfg).unwrap_err();

        let cfg = r#"
            some_field = 123
            tls_certificate = "server.crt"
        "#;
        toml::from_str::<OuterConfig>(cfg).unwrap_err();

        let cfg = r#"
            some_field = 123
            tls_private_key = "server.key"
        "#;
        toml::from_str::<OuterConfig>(cfg).unwrap_err();

        let cfg = r#"
            some_field = 123
            tls_certificate = "server.crt"
            tls_private_key = "server.key"
        "#;
        toml::from_str::<OuterConfig>(cfg).unwrap_err();

        let cfg = r#"
            some_field = 123
            tls_address = "1.2.3.4:443"
            tls_private_key = "server.key"
        "#;
        toml::from_str::<OuterConfig>(cfg).unwrap_err();

        let cfg = r#"
            some_field = 123
            tls_address = "1.2.3.4:443"
            tls_certificate = "server.crt"
        "#;
        toml::from_str::<OuterConfig>(cfg).unwrap_err();
    }
}
