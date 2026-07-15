// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Following the logic of the hyper-rustls server example:
// https://github.com/rustls/hyper-rustls/blob/main/examples/server.rs
// under MIT license OR Apache-2.0

use std::io::{self, Cursor, ErrorKind};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, ready};

use anyhow::Context;
use futures::TryStreamExt;
use http::uri::{Authority, PathAndQuery, Scheme, Uri};
use hyper::header::{HOST, HeaderValue};
use hyper::{Request, StatusCode};
use pin_project::pin_project;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{Accept, TlsAcceptor};
use tracing::error;

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
pub async fn terminate_tls_to_listener<ReadFile: ReadFileFn, Listen: Listener>(
    read_file: ReadFile,
    certs_path: &Path,
    private_key_path: &Path,
    listener: Listen,
) -> anyhow::Result<impl Listener + use<ReadFile, Listen>> {
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
    let certs: Result<_, _> = CertificateDer::pem_reader_iter(&mut Cursor::new(certs)).collect();
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
    PrivateKeyDer::from_pem_reader(&mut Cursor::new(key))
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
    // Disable sketchy optimizations, even if already defaulted to off.
    server_config.send_half_rtt_data = false;
    server_config.send_tls13_tickets = 0;
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
            let connection = LazyHandshake::Handshaking(tls_acceptor.accept(connection));
            async move { Ok((connection, socket_addr)) }
        })
    }
}

// Why go through all the trouble of writing this instead of just directly using
// tls_acceptor.accept(connection) as a connection? Because if the listener above
// (apply_tls_acceptor) does TLS handshakes while accepting connections, then TLS
// handshakes will be performed inside of the accept-loop, preventing more than one
// handshake from being performed concurrently, which can even allow evil clients
// to block all other connections to the server.
//
// We also log any errors that happen as a workaround for hyper swallowing the
// details of WHY it's unable to read/write a connection, which made it hard to
// troubleshoot TLS-related errors.
#[pin_project(project = LazyHandshakeProjection)]
enum LazyHandshake<C> {
    Handshaking(#[pin] Accept<C>),
    Accepted(#[pin] TlsStream<C>),
    Rejected,
}

impl<C: AsyncRead + AsyncWrite + Unpin> LazyHandshake<C> {
    fn poll_connection(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<std::io::Result<Pin<&mut TlsStream<C>>>> {
        use LazyHandshakeProjection as LHP;

        if let LHP::Handshaking(accept) = self.as_mut().project() {
            match ready!(accept.poll(cx)) {
                Ok(tls_stream) => self.set(Self::Accepted(tls_stream)),
                Err(err) => {
                    self.set(Self::Rejected);
                    error!("TLS handshake error: {err}");
                    return Poll::Ready(Err(err));
                }
            }
        }

        let LHP::Accepted(connection) = self.project() else {
            // Eh, we don't log this because the hyper library seems to attempt one more
            // use after getting an error, so this would unhelpfully double-log all errors.
            return Poll::Ready(Err(ErrorKind::ConnectionAborted.into()));
        };
        Poll::Ready(Ok(connection))
    }
}

impl<C: AsyncRead + AsyncWrite + Unpin> AsyncRead for LazyHandshake<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.poll_connection(cx))?
            .poll_read(cx, buf)
            .map_err(log_error("Reading"))
    }
}

impl<C: AsyncRead + AsyncWrite + Unpin> AsyncWrite for LazyHandshake<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        ready!(self.poll_connection(cx))?
            .poll_write(cx, buf)
            .map_err(log_error("Writing to"))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Result<(), std::io::Error>> {
        ready!(self.poll_connection(cx))?
            .poll_flush(cx)
            .map_err(log_error("Flushing"))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Result<(), std::io::Error>> {
        ready!(self.poll_connection(cx))?
            .poll_shutdown(cx)
            .map_err(log_error("Shutting down"))
    }

    // fn poll_write_vectored(
    //     self: Pin<&mut Self>,
    //     cx: &mut std::task::Context,
    //     bufs: &[std::io::IoSlice],
    // ) -> Poll<Result<usize, std::io::Error>> {
    //     ready!(self.poll_connection(cx))?
    //         .poll_write_vectored(cx, bufs)
    //         .map_err(log_error("Writing to"))
    // }
    //
    // // Eh... this might be a dangerous impl because it returns false until the connection has
    // // been interacted with...
    // fn is_write_vectored(&self) -> bool {
    //     matches!(self, Self::Accepted(c) if c.is_write_vectored())
    // }
}

fn log_error(action: &str) -> impl '_ + Fn(std::io::Error) -> std::io::Error {
    move |err| {
        // Some clients *cough*wget*cough* fail to properly send a close_notify before closing
        // TLS connections. This is technically wrong, but in practice it's only insecure for
        // protocols that can't detect truncation. Modern HTTP can detect truncation, so this
        // error can be safely ignored. For details, see:
        // https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
        if err.kind() != ErrorKind::UnexpectedEof {
            error!("{action} TLS connection failed: {err}");
        }
        err
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
                    );
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

    use std::pin::pin;

    use futures::{FutureExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::test::FakeNetwork;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct OuterConfig {
        some_field: u32,

        #[serde(flatten)]
        #[serde(deserialize_with = "TlsConfig::deserialize_option")]
        pub tls_config: Option<TlsConfig>,
    }

    const DUMMY_CRT: &str = "dummy.crt";
    const DUMMY_CRT_CONTENTS: &str = "
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUDnZPqY+OBUMt5vB0WhCB6xhw63gwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA3MDExMDA5NThaFw0yNDA3
MzExMDA5NThaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCPlYU5UDU31ywMoMRlgINLkmcsEkRcYY86/sksljfs
qoubfD4l0NSa7OfaYSz17BcJsQ1Vo/v1ojnp1o2I21mkgWZJoU8uSYQTU012VD1d
8tefTupg93ADW2hNvAKHFlB6V0RTpou83unqQkqxYtSTGIFVtpS7C/yLqGucMN3y
57Rq91AJDhekxlgSd7DcJTjjIpb9ZJWrLKkLDmOJsaIA5avV/fdcBwa/B7gMSxQ8
agINH1N/Tw8QlYyRCkPx9X/szpsr7RClWiQD9UeUcxhQaHUpj0KTNl5qzW4nh5kN
1leIchQG6lzv4/1yRyO5/X3lSuLxElC/fWKV6tN1nl69AgMBAAGjUzBRMB0GA1Ud
DgQWBBQAqNfZwQ15+Jfvz9gWPEzDE7FwDjAfBgNVHSMEGDAWgBQAqNfZwQ15+Jfv
z9gWPEzDE7FwDjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAM
/L3huGOReiEq730ljsnloMggk1dthrFp1Rwi8n++kSWVlWuO8OL5H3nVj8uhOcZo
gaUvzgYpM+/k7hXLgKQUxetlZVhP+iMbUXnIPErohkHnR+V6PJ7ogX/wCWLDOm1B
+9cj2IAdju1AE27Zhd6Wtp3TFvRiNjOOtYUBSDpx1VJtjjXMulo5BpvM00i8GQbR
UWKnLAxVm3qEq+AhmQ6hsKfAeC7of7LzT82ebOhPqW3yS3NwJQTRLTRFXpQNCigx
mDuX2EuB7w+clWVUZgtSmpXrq568z4nTxawKFTpcJcYp74QrVqk18Z1CZzYAXU15
DXY1H0MxC8/9nZIZNL54
-----END CERTIFICATE-----
    ";

    const DUMMY_KEY: &str = "dummy.key";
    const DUMMY_KEY_CONTENTS: &str = "
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCPlYU5UDU31ywM
oMRlgINLkmcsEkRcYY86/sksljfsqoubfD4l0NSa7OfaYSz17BcJsQ1Vo/v1ojnp
1o2I21mkgWZJoU8uSYQTU012VD1d8tefTupg93ADW2hNvAKHFlB6V0RTpou83unq
QkqxYtSTGIFVtpS7C/yLqGucMN3y57Rq91AJDhekxlgSd7DcJTjjIpb9ZJWrLKkL
DmOJsaIA5avV/fdcBwa/B7gMSxQ8agINH1N/Tw8QlYyRCkPx9X/szpsr7RClWiQD
9UeUcxhQaHUpj0KTNl5qzW4nh5kN1leIchQG6lzv4/1yRyO5/X3lSuLxElC/fWKV
6tN1nl69AgMBAAECggEAJQHhNg31wYA8kr6nEBBJBuPjoqjMpNDiZU7BFDRdkqq8
U+V4cS+7dHjmI1OTjoj8wRs4uB+Nc9iNu7b4gNMkbjGJ5yVj7qa1G3QHjZ2VuY67
Q4zH/RkZbkwTfKGeNyopsPaoHjVZY+NCgAX5EXJLHuSchTaLbBBhVa+hmL7Bnfb2
oX2wjtjY4sdmpBySORSUHNn79mZYyzDpqiFxpI+TusuvWv8Wg4Cc69h35NxA3cCu
D7BeKOw+qnSiAQCP4wn2ZcH/aREZIFTcd+algn+FGR72Q4Zmprb69dDrqyt5dkQw
8cel4WPyG/oP6Ad7geqt3o+AxXbeP0MOEWf6QpQMcwKBgQC8a2VehGMiLfCIFN85
Pw9/PhvUWus6EDl/krP0y1SOxWoVeo9aDNl2YRYAkFwCKvyNm5/AOpJn+MnUR5Fn
P5jLIRGchS3GDbdoBHFKVqOmS9v3UXRz7E+nBwAmr6tELmopfyvTCCFPZ/MBxxl6
olP+zU0j1nAQnMAo3FBkd1ncTwKBgQDDFVnxY4v6NLrcCgE3o8V/D9lN1SRW/1ZL
8NaXHjBU33t2u3szdif5AlSgNTFu7RGVsGUbv1bWHCnjtpNwZMSbKCp9tPppBpb0
NrH49yO5VIBBVfgVTD0dklisLtyeE/bs+0EPiNcEyZXDemMB6694krzp4Y5NeHok
WzTKU8sVMwKBgQCP/q9wpVIxm9Q322OhF01bm/aeuoEMVbvrgA0hZocPuVVSZuDJ
HArRSm8LLUfzrDBodGeI+/pJlTuBjNRViKfXjUUtTiZmNrNUvhhqjH3yqATKJKkP
sqhI6LO33QbRS3t8jSDL3Wm/ipyPXj5dl1MD5pgubEImn/THBWA293NoRwKBgQCR
5841dDalE/sNx43Rh3OW7MuiIt/jEWYBtkdJDxMm5174FpC2lJCg9NVGXYJzbGvS
gPOeJSVVTgsmfM8ZKMTDJu9gxZLkKkGMtbu2cWEOo9ypARtjEnpDO8mGPiZTNKth
4ylt7PKkagDRCyAxt4ytqVIRutkrqAfyWSTKjpE9cQKBgQChGvvsRZK+cQgDCUtH
oySgbr9XFnC3+dBKldOGP0chqeA/P3jIcU20Kc15NMdsU6d2AlO8uwJqfYGdbaOL
IGjinBXsm5WnFdcHq2Ba5rZ1Qy0WrGSxUvVz5o0k16ysqdyg+q/4YgqnWHdTVItU
lEBAX5CJVbpw81HeTbnlo0Jy3A==
-----END PRIVATE KEY-----
    ";

    async fn read_dummy_file(path: PathBuf) -> std::io::Result<Vec<u8>> {
        if path == Path::new(DUMMY_CRT) {
            return Ok(DUMMY_CRT_CONTENTS.as_bytes().to_vec());
        }
        if path == Path::new(DUMMY_KEY) {
            return Ok(DUMMY_KEY_CONTENTS.as_bytes().to_vec());
        }
        Err(ErrorKind::NotFound.into())
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

    // A mute client shouldn't block all subsequent incoming TLS connections.
    // The server accepts connections one at a time, so that's a bad time to
    // perform TLS handshakes because they may block.
    #[tokio::test]
    async fn regression_accepting_connection_does_not_talk_to_it() {
        let server_addr = "1.2.3.4:443".parse().unwrap();
        let network = FakeNetwork::new();

        let tls_listener = terminate_tls_to_listener(
            read_dummy_file,
            Path::new(DUMMY_CRT),
            Path::new(DUMMY_KEY),
            network.listen(server_addr).unwrap(),
        )
        .await
        .unwrap();
        let mut connections = pin!(tls_listener());

        // Open a connection but deliberately don't talk to it.
        let _mute_client = network.connect(server_addr).await.unwrap();

        // We should be able to accept the connection immediately without it
        // needing to wait for the client to talk.
        connections.next().now_or_never().unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn regression_invalid_handshakes_dont_panic() {
        let server_addr = "1.2.3.4:443".parse().unwrap();
        let network = FakeNetwork::new();

        let tls_listener = terminate_tls_to_listener(
            read_dummy_file,
            Path::new(DUMMY_CRT),
            Path::new(DUMMY_KEY),
            network.listen(server_addr).unwrap(),
        )
        .await
        .unwrap();
        let mut connections = pin!(tls_listener());

        let mut client_conn = network.connect(server_addr).await.unwrap();
        client_conn.write_all(b"invalid handshake").await.unwrap();

        let (mut connection, _addr) = connections.next().await.unwrap().unwrap();
        // First read triggers an error...
        connection.read_to_end(&mut vec![]).await.unwrap_err();
        // Second one might poll connection after TLS handshake has already failed,
        // potentially causing panic.
        connection.read_to_end(&mut vec![]).await.unwrap_err();
    }
}
