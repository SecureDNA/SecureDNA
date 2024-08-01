// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Connection, SqlCertificateId, SqlOffsetDateTime};
use certificates::Id;
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
