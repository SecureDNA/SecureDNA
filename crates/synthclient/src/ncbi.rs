// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use shared_types::requests::RequestId;
use thiserror::Error;
use tracing::info;

use crate::fetch::{fetch, FetchError};

#[derive(Debug, Error)]
pub enum NcbiError {
    #[error("Could not query NCBI database. Caused by: {0}")]
    RequestFailed(FetchError),
    #[error("Could not query NCBI database. Got status {0} with {1}")]
    RequestFailedWithStatus(u16, String),
    #[error("Invalid accession number {0}")]
    InvalidAccession(String),
}

pub async fn download_fasta_by_acc_number(
    request_id: &RequestId,
    acc: String,
) -> Result<String, NcbiError> {
    let url = format!(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi?db=nuccore&rettype=fasta&id={}",
        acc.trim()
    );
    info!("{request_id}: requesting FASTA from NCBI URL: {url}");

    let response = fetch(&url).await.map_err(NcbiError::RequestFailed)?;

    let status = response.status;
    let text = response.data;

    if status != 200 {
        // sometimes, the NCBI API returns with a 400 instead of a 404 for an unknown
        // accession (seems to be a proper 404 for HEAD, but 400 for GET?)
        // as for the formatting... ¯\_(ツ)_/¯ the content type is text/plain
        if status == 404 || text.contains("F+a+i+l+e+d++t+o++u+n+d+e+r+s+t+a+n+d++i+d") {
            Err(NcbiError::InvalidAccession(acc))
        } else {
            let mut text = text;
            text.truncate(2000); // let's not log more than this
            Err(NcbiError::RequestFailedWithStatus(status, text))
        }
    } else {
        Ok(text)
    }
}
