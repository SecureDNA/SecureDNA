// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

pub use persistence::Connection;
use persistence::{params, rusqlite::OptionalExtension, tokio_rusqlite, Migrations, OpenError, M};

pub async fn open_db(path: impl AsRef<Path>) -> Result<Connection, OpenError> {
    persistence::open_db(
        path,
        // do not modify these migrations, instead create a new migration
        Migrations::from_iter([M::up(include_str!("migration-00.sql"))]),
    )
    .await
}

pub async fn upsert_server_version(
    conn: &Connection,
    domain: String,
    server_version: u64,
) -> Result<(), tokio_rusqlite::Error> {
    conn.call(move |conn| {
        conn.execute(
            r#"
            INSERT OR REPLACE INTO servers (domain, server_version)
            VALUES (?1, ?2);
            "#,
            params![domain, server_version,],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn query_last_server_version(
    conn: &Connection,
    domain: String,
) -> Result<Option<u64>, tokio_rusqlite::Error> {
    let server_version = conn
        .call(move |conn| {
            let id = conn
                .query_row(
                    r#"
                    SELECT server_version FROM servers
                    WHERE domain = ?1;
                    "#,
                    params![domain],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(id)
        })
        .await?;
    Ok(server_version)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_open_db() {
        open_db(":memory:").await.unwrap();
    }

    #[tokio::test]
    async fn test_upsert_and_query_server_version() {
        let conn = open_db(":memory:").await.unwrap();

        let domain = "example.com".to_string();
        let server_version = 1;
        upsert_server_version(&conn, domain.clone(), server_version)
            .await
            .unwrap();

        let result = query_last_server_version(&conn, domain).await.unwrap();
        assert_eq!(result, Some(server_version));
    }

    #[tokio::test]
    async fn test_update_server_version() {
        let conn = open_db(":memory:").await.unwrap();

        let domain = "example.com".to_string();
        let initial_version = 1;
        let updated_version = 2;

        upsert_server_version(&conn, domain.clone(), initial_version)
            .await
            .unwrap();

        upsert_server_version(&conn, domain.clone(), updated_version)
            .await
            .unwrap();

        let result = query_last_server_version(&conn, domain).await.unwrap();
        assert_eq!(result, Some(updated_version));
    }

    #[tokio::test]
    async fn test_query_non_existent_domain() {
        let conn = open_db(":memory:").await.unwrap();

        let non_existent_domain = "nonexistent.com".to_string();
        let result = query_last_server_version(&conn, non_existent_domain)
            .await
            .unwrap();
        assert_eq!(result, None);
    }
}
