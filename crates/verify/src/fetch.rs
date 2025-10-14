// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Context};
use certificates::{TokenBundle, VerifierTokenGroup};
use reqwest::Url;

pub trait HistoryFetcher {
    fn fetch_update_log(
        &self,
        history_url: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<String>>;

    fn fetch_token(
        &self,
        history_url: &str,
        rotation: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<TokenBundle<VerifierTokenGroup>>>;
}

pub struct NetworkHistoryFetcher;

impl HistoryFetcher for NetworkHistoryFetcher {
    async fn fetch_update_log(&self, history_url: &str) -> anyhow::Result<String> {
        get_github_text(history_url, "refs/heads/main/update.log").await
    }

    async fn fetch_token(
        &self,
        history_url: &str,
        rotation: i64,
    ) -> anyhow::Result<TokenBundle<VerifierTokenGroup>> {
        let contents = get_github_text(
            history_url,
            &format!("refs/heads/main/tokens/verifier-token-{rotation}.vt"),
        )
        .await?;
        let key = TokenBundle::from_file_contents(contents)?;
        Ok(key)
    }
}

fn github_raw_url(repo_url: &str, path: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(repo_url).context("Failed to parse GitHub URL")?;
    if url.host_str() != Some("github.com") {
        anyhow::bail!("unrecognized history url");
    }
    url.set_host(Some("raw.githubusercontent.com"))
        .context("Failed to set host on GitHub URL")?;
    url.path_segments_mut()
        .map_err(|()| anyhow!("repo_url is a cannot-be-a-base URL?"))?
        .pop_if_empty()
        .push("");
    Ok(url.join(path.trim_start_matches('/'))?)
}

/// Fetch a UTF-8 text file from a public GitHub repo.
async fn get_github_text(repo_url: &str, path: &str) -> anyhow::Result<String> {
    let bytes = reqwest::get(github_raw_url(repo_url, path)?)
        .await?
        .bytes()
        .await?;
    Ok(std::str::from_utf8(&bytes)?.to_owned())
}

#[cfg(test)]
mod tests {
    use crate::fetch::github_raw_url;

    #[tokio::test]
    async fn make_raw_url() {
        // No slashes:
        assert_eq!(
            github_raw_url(
                "https://github.com/example/repo",
                "refs/heads/main/Cargo.toml"
            )
            .unwrap()
            .as_str(),
            "https://raw.githubusercontent.com/example/repo/refs/heads/main/Cargo.toml",
        );

        // Slash at end of repo URL:
        assert_eq!(
            github_raw_url(
                "https://github.com/example/repo/",
                "refs/heads/main/Cargo.toml"
            )
            .unwrap()
            .as_str(),
            "https://raw.githubusercontent.com/example/repo/refs/heads/main/Cargo.toml",
        );

        // Slash at start of path URL:
        assert_eq!(
            github_raw_url(
                "https://github.com/example/repo",
                "/refs/heads/main/Cargo.toml"
            )
            .unwrap()
            .as_str(),
            "https://raw.githubusercontent.com/example/repo/refs/heads/main/Cargo.toml",
        );

        // Both slashes:
        assert_eq!(
            github_raw_url(
                "https://github.com/example/repo/",
                "/refs/heads/main/Cargo.toml"
            )
            .unwrap()
            .as_str(),
            "https://raw.githubusercontent.com/example/repo/refs/heads/main/Cargo.toml",
        );
    }
}
