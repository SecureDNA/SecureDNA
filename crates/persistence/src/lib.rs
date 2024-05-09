// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::{Path, PathBuf};

pub use rusqlite;
use rusqlite::{
    types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef},
    ToSql,
};
pub use rusqlite_migration::{self, Migrations, M};
pub use tokio_rusqlite::{self, params, Connection};

use shared_types::synthesis_permission::{Region, SynthesisPermission};

pub mod open_events;

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("couldn't initialize connection to db at {0:?}: {1}")]
    Initializing(PathBuf, #[source] tokio_rusqlite::Error),
    #[error("couldn't migrate db at {0:?} to latest schema version: {1}")]
    Migrating(PathBuf, #[source] tokio_rusqlite::Error),
}

pub async fn open_db(
    path: impl AsRef<Path>,
    migrations: Migrations<'static>,
) -> Result<Connection, OpenError> {
    let path = path.as_ref();

    let conn = Connection::open(path)
        .await
        .map_err(|e| OpenError::Initializing(path.to_owned(), e))?;

    // make sure db is in WAL journal mode (https://www.sqlite.org/wal.html), which is faster
    // and the disadvantages don't affect us
    // also enable foreign keys
    conn.call(|sync_conn| {
        sync_conn.pragma_update(None, "journal_mode", "WAL")?;
        sync_conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(())
    })
    .await
    .map_err(|e| OpenError::Initializing(path.to_owned(), e))?;

    // run migrations. rusqlite_migrations has an async feature, but it's in alpha
    conn.call(move |sync_conn| {
        migrations
            .to_latest(sync_conn)
            .map_err(|e| tokio_rusqlite::Error::Other(e.into()))?;
        Ok(())
    })
    .await
    .map_err(|e| OpenError::Migrating(path.to_owned(), e))?;

    Ok(conn)
}

/// Get the UTC unix timestamp
pub fn now_utc() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Get the UTC timestamp for 1 day ago
pub fn one_day_ago_utc() -> i64 {
    (time::OffsetDateTime::now_utc() - time::Duration::days(1)).unix_timestamp()
}

/// Wrapper that implements ToSql / FromSql for Region
#[derive(Debug, Clone, Copy)]
pub struct SqlRegion(pub Region);

impl ToSql for SqlRegion {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'static>> {
        // manually doing the conversion here to
        // a) avoid allocating
        // b) be explicit about conversions so we remember to migrate old values if we change these
        Ok(ToSqlOutput::from(match self.0 {
            Region::Us => "us",
            Region::Eu => "eu",
            Region::Prc => "prc",
            Region::All => "all",
        }))
    }
}

impl FromSql for SqlRegion {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let s = value.as_str()?;
        match s {
            "us" => Ok(SqlRegion(Region::Us)),
            "eu" => Ok(SqlRegion(Region::Eu)),
            "prc" => Ok(SqlRegion(Region::Prc)),
            "all" => Ok(SqlRegion(Region::All)),
            _ => Err(FromSqlError::Other(
                format!("Unknown region str: {s:?}").into(),
            )),
        }
    }
}

impl From<Region> for SqlRegion {
    fn from(value: Region) -> Self {
        Self(value)
    }
}

impl From<SqlRegion> for Region {
    fn from(value: SqlRegion) -> Self {
        value.0
    }
}

/// Wrapper that implements ToSql / FromSql for certificates::Id
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqlCertificateId(pub certificates::Id);

impl ToSql for SqlCertificateId {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.0.as_ref().to_sql()
    }
}

impl FromSql for SqlCertificateId {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let bytes =
            <[u8; 16]>::try_from(value.as_bytes()?).map_err(|e| FromSqlError::Other(e.into()))?;
        Ok(Self(certificates::Id::from(bytes)))
    }
}

impl From<certificates::Id> for SqlCertificateId {
    fn from(value: certificates::Id) -> Self {
        Self(value)
    }
}

impl From<SqlCertificateId> for certificates::Id {
    fn from(value: SqlCertificateId) -> Self {
        value.0
    }
}

/// Wrapper that implements ToSql / FromSql for SynthesisPermission
#[derive(Debug, Clone, Copy)]
pub struct SqlSynthesisPermission(pub SynthesisPermission);

impl ToSql for SqlSynthesisPermission {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'static>> {
        // Manually doing the conversion here to
        // a) avoid allocating
        // b) be explicit about conversions so we remember to migrate old values if we change these
        Ok(ToSqlOutput::from(match self.0 {
            SynthesisPermission::Granted => "granted",
            SynthesisPermission::Denied => "denied",
        }))
    }
}

impl FromSql for SqlSynthesisPermission {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let s = value.as_str()?;
        match s {
            "granted" => Ok(SqlSynthesisPermission(SynthesisPermission::Granted)),
            "denied" => Ok(SqlSynthesisPermission(SynthesisPermission::Denied)),
            _ => Err(FromSqlError::Other(
                format!("Unknown SynthesisPermission value: {s:?}").into(),
            )),
        }
    }
}
