// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Connection, SqlCertificateId, SqlOffsetDateTime};
use certificates::{ChainTraversal, Id, SynthesizerTokenGroup, TokenBundle};
use rusqlite::params;

pub async fn query_bp_per_day_per_client(
    conn: &Connection,
    start_date: impl Into<SqlOffsetDateTime>,
    end_date: impl Into<SqlOffsetDateTime>,
    table_name: &'static str,
    column_name: &'static str,
) -> Result<Vec<(SqlOffsetDateTime, Id, u64)>, tokio_rusqlite::Error> {
    let start_date = start_date.into();
    let end_date = end_date.into();
    conn.call(move |conn| {
        let result = conn
            .prepare(&format!(
                r#"
                SELECT
                  -- round timestamp to nearest date, then cast back to timestamp integer
                  CAST(strftime('%s', date(timestamp_utc, 'unixepoch')) AS INTEGER) as datestamp,
                  client_mid,
                  COALESCE(SUM({column_name}), 0)
                FROM {table_name}
                WHERE timestamp_utc BETWEEN ?1 AND ?2
                GROUP BY datestamp, client_mid
                ORDER BY datestamp, client_mid
                "#
            ))?
            .query_map(params![start_date, end_date], |row| {
                Ok((
                    row.get::<_, SqlOffsetDateTime>(0)?,
                    row.get::<_, SqlCertificateId>(1)?.0,
                    row.get::<_, u64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(result)
    })
    .await
}

pub async fn query_orders_per_day_per_client(
    conn: &Connection,
    start_date: impl Into<SqlOffsetDateTime>,
    end_date: impl Into<SqlOffsetDateTime>,
    table_name: &'static str,
) -> Result<Vec<(SqlOffsetDateTime, Id, u64)>, tokio_rusqlite::Error> {
    let start_date = start_date.into();
    let end_date = end_date.into();
    conn.call(move |conn| {
        let result = conn
            .prepare(&format!(
                r#"
                SELECT
                  -- round timestamp to nearest date, then cast back to timestamp integer
                  CAST(strftime('%s', date(timestamp_utc, 'unixepoch')) AS INTEGER) as datestamp,
                  client_mid,
                  count(*) as orders
                FROM {table_name}
                WHERE timestamp_utc BETWEEN ?1 AND ?2
                GROUP BY datestamp, client_mid
                ORDER BY datestamp, client_mid
                "#,
            ))?
            .query_map(params![start_date, end_date], |row| {
                Ok((
                    row.get::<_, SqlOffsetDateTime>(0)?,
                    row.get::<_, SqlCertificateId>(1)?.0,
                    row.get::<_, u64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(result)
    })
    .await
}

pub async fn query_exceedances_per_day_per_client(
    conn: &Connection,
    start_date: impl Into<SqlOffsetDateTime>,
    end_date: impl Into<SqlOffsetDateTime>,
) -> Result<Vec<(SqlOffsetDateTime, Id, u64)>, tokio_rusqlite::Error> {
    let start_date = start_date.into();
    let end_date = end_date.into();
    conn.call(move |conn| {
        let result = conn
            .prepare(
                r#"
                SELECT
                  -- round timestamp to nearest date, then cast back to timestamp integer
                  CAST(strftime('%s', date(timestamp_utc, 'unixepoch')) AS INTEGER) as datestamp,
                  client_mid,
                  count(*) as exceedances
                FROM ratelimit_exceedances
                WHERE timestamp_utc BETWEEN ?1 AND ?2
                GROUP BY datestamp, client_mid
                ORDER BY datestamp, client_mid
                "#,
            )?
            .query_map(params![start_date, end_date], |row| {
                Ok((
                    row.get::<_, SqlOffsetDateTime>(0)?,
                    row.get::<_, SqlCertificateId>(1)?.0,
                    row.get::<_, u64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(result)
    })
    .await
}

#[derive(Debug, PartialEq, Eq)]
pub struct TokenLimitData {
    /// The token's rate limit, in DNA base pairs per day.
    pub rate_limit: u64,
    /// Email addresses in the issuer description fields of this token and all
    /// superior certs, excluding those ending in `@securedna.org`.
    pub email_addresses: Vec<String>,
}

impl TokenLimitData {
    pub fn from_bytes(token_bytes: &[u8]) -> Option<Self> {
        TokenBundle::<SynthesizerTokenGroup>::from_file_contents(token_bytes)
            .ok()
            .map(|bundle| {
                let rate_limit = bundle.token.max_dna_base_pairs_per_day();
                let mut email_addresses: Vec<_> = bundle
                    .chain()
                    .into_iter()
                    .flat_map(|c| c.email_addresses())
                    .filter(|email| !email.ends_with("@securedna.org"))
                    .collect();
                email_addresses.sort();
                email_addresses.dedup();
                Self {
                    rate_limit,
                    email_addresses,
                }
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TokenLimitRecord {
    /// The latest time in the range selected over that this token_id was use.
    pub unix_timestamp: i64,
    /// The ID of the token.
    pub token_id: Id,
    /// Data extracted from the token. This is `None` if decoding the cert failed.
    pub data: Option<TokenLimitData>,
}

pub async fn query_token_limits(
    conn: &Connection,
    start_date: impl Into<SqlOffsetDateTime>,
    end_date: impl Into<SqlOffsetDateTime>,
    table_name: &'static str,
) -> Result<Vec<TokenLimitRecord>, tokio_rusqlite::Error> {
    let start_date = start_date.into();
    let end_date = end_date.into();
    conn.call(move |conn| {
        let result = conn
            .prepare(&format!(
                r#"
                SELECT MAX(s.timestamp_utc), s.client_mid, c.client_token
                FROM {table_name} s
                JOIN certs c ON s.client_mid = c.client_mid
                WHERE s.timestamp_utc BETWEEN ?1 AND ?2
                GROUP BY s.client_mid
                ORDER BY MAX(s.timestamp_utc)
                "#,
            ))?
            .query_map(params![start_date, end_date], |row| {
                let time = row.get::<_, SqlOffsetDateTime>(0)?;
                let unix_timestamp = time.0.unix_timestamp();
                let token_id = row.get::<_, SqlCertificateId>(1)?.0;
                let token_bytes = row.get::<_, Vec<u8>>(2)?;
                Ok(TokenLimitRecord {
                    unix_timestamp,
                    token_id,
                    data: TokenLimitData::from_bytes(&token_bytes),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(result)
    })
    .await
}
