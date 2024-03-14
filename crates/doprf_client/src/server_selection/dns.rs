// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use bytes::Bytes;

use crate::{error::DOPRFError, retry_if::retry_if};
use http_client::BaseApiClient;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait DnsLookup {
    /// Lookup a domain name, and return `true` if it exists.
    /// The string MUST be a bare domain, not a URL—it must not have a scheme or path component.
    async fn lookup(&self, domain: &str) -> Result<bool, LookupError>;
}

/// DNS lookup via RFC 8484, over an HTTPS API
#[derive(Debug, Clone)]
pub struct DnsOverHttps {
    api_client: BaseApiClient,
    dns_over_https_endpoint: String,
}

impl DnsOverHttps {
    /// Construct a new DnsOverHttps instance using the domain and optional port
    /// of a DNS-over-HTTPS resolver.
    ///
    /// ```rust
    /// # use doprf_client::server_selection::dns::DnsOverHttps;
    /// let cloudflare_dns = DnsOverHttps::new("1.1.1.1");
    /// let google_dns = DnsOverHttps::new("dns.google");
    /// let localhost = DnsOverHttps::new("localhost:8000");
    /// ```
    pub fn new(server: &str) -> Self {
        Self {
            api_client: BaseApiClient::new_external(),
            dns_over_https_endpoint: format!("https://{server}/dns-query"),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DnsLookup for &DnsOverHttps {
    async fn lookup(&self, domain: &str) -> Result<bool, LookupError> {
        let mut builder = dns_parser::Builder::new_query(0, true);
        builder.add_question(
            domain,
            false,
            // TODO: given that QueryType::All causes cloudflare to return NotImplemented, is this the best record type to use?
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );

        let packet: Bytes = builder.build().unwrap().into();

        // this retry is just for http errors, not missing dns entries, which are expected and don't produce an error
        // TODO: this retry might be too slow
        let response = retry_if(
            || {
                async {
                    Ok(self
                        .api_client
                        .bytes_bytes_post(
                            &self.dns_over_https_endpoint,
                            packet.clone(), // bytes::Bytes is rc'd, so this is cheap
                            "application/dns-message",
                            "application/dns-message",
                        )
                        .await?)
                }
            },
            |e: &DOPRFError| e.is_retriable(),
        )
        .await?;

        let parsed_response = dns_parser::Packet::parse(&response)
            .map_err(|e| LookupError::DnsResponse(e, response.clone()))?;

        Ok(!parsed_response.answers.is_empty())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DnsLookup for DnsOverHttps {
    async fn lookup(&self, domain: &str) -> Result<bool, LookupError> {
        (&self).lookup(domain).await
    }
}

/// DNS lookup via tokio::net::lookup_host, which is via std::net::to_socket_addrs, which is
/// ultimately via libc getaddrinfo
///
/// NativeDns::lookup will currently never return errors—all errors are treated as NXDOMAIN/Ok(false).
/// This may change in the future.
///
/// ```rust
/// # use doprf_client::server_selection::dns::{DnsLookup, NativeDns};
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// assert!(NativeDns.lookup("localhost").await.unwrap());
/// # })
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy)]
pub struct NativeDns;

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl DnsLookup for &NativeDns {
    async fn lookup(&self, domain: &str) -> Result<bool, LookupError> {
        // this can technically fail for other reasons than NXDOMAIN, but it's rare
        Ok(tokio::net::lookup_host((domain, 80)).await.is_ok())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl DnsLookup for NativeDns {
    async fn lookup(&self, domain: &str) -> Result<bool, LookupError> {
        (&self).lookup(domain).await
    }
}

#[derive(thiserror::Error, Debug)]
pub enum LookupError {
    #[error("http error: {0}")]
    Fetch(#[from] DOPRFError),
    #[error("bad http status: {0}")]
    Status(u16),
    #[error("error parsing dns response: {0} ({1:?})")]
    DnsResponse(#[source] dns_parser::Error, Bytes),
}

pub mod test_utils {
    use std::{collections::HashMap, sync::Arc};

    use super::{DnsLookup, LookupError};

    type LookupResultGenerator = Arc<dyn Fn() -> Option<LookupError> + Send + Sync>;

    #[derive(Clone, Default)]
    pub struct MockDns {
        domain_results: HashMap<String, LookupResultGenerator>,
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl DnsLookup for &MockDns {
        async fn lookup(&self, domain: &str) -> Result<bool, LookupError> {
            match self.domain_results.get(domain) {
                None => Ok(false),
                Some(f) => match f() {
                    Some(e) => Err(e),
                    None => Ok(true),
                },
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl DnsLookup for MockDns {
        async fn lookup(&self, domain: &str) -> Result<bool, LookupError> {
            (&self).lookup(domain).await
        }
    }

    impl MockDns {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_known_domain(mut self, domain: impl Into<String>) -> Self {
            self.domain_results.insert(domain.into(), Arc::new(|| None));
            self
        }

        pub fn with_error(
            mut self,
            domain: impl Into<String>,
            errgen: impl Fn() -> LookupError + Send + Sync + 'static,
        ) -> Self {
            self.domain_results
                .insert(domain.into(), Arc::new(move || Some(errgen())));
            self
        }

        pub fn with_transient_error(
            mut self,
            domain: impl Into<String>,
            errgen: impl Fn() -> LookupError + Send + Sync + 'static,
            count: usize,
        ) -> Self {
            let count = std::sync::RwLock::from(count);
            self.domain_results.insert(
                domain.into(),
                Arc::new(move || {
                    if *count.read().unwrap() == 0 {
                        None
                    } else {
                        *count.write().unwrap() -= 1;
                        Some(errgen())
                    }
                }),
            );
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::Future;

    use super::*;

    /// run a boolean function 3 times in case of network flakiness, sleeping .5s in between runs,
    /// returning true as soon as any run returns true, otherwise returning the result of the last run
    async fn flaky<F, FR, E>(f: F) -> Result<bool, E>
    where
        F: Fn() -> FR,
        FR: Future<Output = Result<bool, E>>,
    {
        const TRIES: usize = 3;
        const DUR: Duration = Duration::from_millis(500);

        for _ in 0..TRIES - 1 {
            if f().await.unwrap_or(false) {
                return Ok(true);
            }
            tokio::time::sleep(DUR).await;
        }

        f().await
    }

    // it's not ideal to hit the network during tests, but we don't want to set up a DNS resolver
    // in CI right now. Cloudflare's DNS-over-HTTPS endpoint should be relatively stable, as should
    // the native DNS in Github Actions.

    #[tokio::test]
    async fn lookup_real_native() {
        assert!(flaky(|| NativeDns.lookup("securedna.org")).await.unwrap());
    }

    #[tokio::test]
    async fn lookup_real_doh() {
        let dns = DnsOverHttps::new("1.1.1.1");
        assert!(flaky(|| dns.lookup("securedna.org")).await.unwrap());
    }

    #[tokio::test]
    async fn lookup_fake_native() {
        assert!(!flaky(
            || NativeDns.lookup("donotmakethissubdomainorthetestswillbreak.securedna.org",)
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn lookup_fake_doh() {
        let dns = DnsOverHttps::new("1.1.1.1");
        assert!(
            !flaky(|| dns.lookup("donotmakethissubdomainorthetestswillbreak.securedna.org",))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_mock_dns() {
        // basic tests to make sure mock dns is working correctly
        let mock = test_utils::MockDns::new()
            .with_known_domain("localhost")
            .with_known_domain("securedna.org")
            .with_error("google.com", || LookupError::Status(500))
            .with_transient_error("example.org", || LookupError::Status(500), 1);
        assert!(mock.lookup("localhost").await.unwrap());
        assert!(mock.lookup("securedna.org").await.unwrap());
        assert!(!mock.lookup("asjdakjhfdkah.com").await.unwrap());
        assert!(matches!(
            mock.lookup("google.com").await,
            Err(LookupError::Status(500))
        ));
        // transient error should go away
        assert!(matches!(
            mock.lookup("example.org").await,
            Err(LookupError::Status(500))
        ));
        assert!(mock.lookup("example.org").await.unwrap());
    }
}
