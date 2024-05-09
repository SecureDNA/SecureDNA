// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use certificates::Id;
use persistence::{
    now_utc, one_day_ago_utc, params, tokio_rusqlite, Migrations, OpenError, SqlCertificateId, M,
};
pub use persistence::{
    open_events::{insert_open_event, last_protocol_version_for_client},
    Connection,
};

pub async fn open_db(path: impl AsRef<Path>) -> Result<Connection, OpenError> {
    persistence::open_db(
        path,
        // do not modify these migrations, instead create a new migration
        Migrations::from_iter([M::up(include_str!("migration-00.sql"))]),
    )
    .await
}

pub async fn insert_keyserve_event(
    conn: &Connection,
    client_mid: Id,
    keyserve_bp: u64,
) -> Result<(), tokio_rusqlite::Error> {
    insert_keyserve_event_at_time(conn, client_mid, keyserve_bp, now_utc()).await
}

async fn insert_keyserve_event_at_time(
    conn: &Connection,
    client_mid: Id,
    keyserve_bp: u64,
    timestamp_utc: i64,
) -> Result<(), tokio_rusqlite::Error> {
    conn.call(move |conn| {
        conn.execute(
            r#"
                INSERT INTO keyserve_events (client_mid, keyserved_bp, timestamp_utc)
                VALUES (?1, ?2, ?3);
                "#,
            params![SqlCertificateId(client_mid), keyserve_bp, timestamp_utc,],
        )?;
        Ok(())
    })
    .await?;

    Ok(())
}

pub async fn insert_ratelimit_exceedance(
    conn: &Connection,
    client_mid: Id,
    attempted_bp: u64,
) -> Result<(), tokio_rusqlite::Error> {
    conn.call(move |conn| {
        conn.execute(
            r#"
            INSERT INTO ratelimit_exceedances (client_mid, attempted_bp, timestamp_utc)
            VALUES (?1, ?2, ?3);
            "#,
            params![SqlCertificateId(client_mid), attempted_bp, now_utc(),],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn query_client_keyserved_bp_last_day(
    conn: &Connection,
    client_mid: Id,
) -> Result<u64, tokio_rusqlite::Error> {
    let sum = conn
        .call(move |conn| {
            let sum = conn.query_row(
                r#"
                SELECT COALESCE(SUM(keyserved_bp), 0)
                FROM keyserve_events
                WHERE client_mid = ?1 AND timestamp_utc >= ?2;
                "#,
                params![SqlCertificateId(client_mid), one_day_ago_utc()],
                |row| row.get(0),
            )?;
            Ok(sum)
        })
        .await?;
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    use certificates::Issued;
    use persistence::open_events::test_utils::make_synth_tokens;

    #[tokio::test]
    async fn test_open_db() {
        open_db(":memory:").await.unwrap();
    }

    #[tokio::test]
    async fn open_and_last_version() {
        let conn = open_db(":memory:").await.unwrap();
        persistence::open_events::test_utils::test_open_and_last_version(conn).await;
    }

    #[tokio::test]
    pub async fn open_inserts_single_cert() {
        let conn = open_db(":memory:").await.unwrap();
        persistence::open_events::test_utils::test_open_inserts_single_cert(conn).await;
    }

    #[tokio::test]
    async fn insert_and_query() {
        let conn = open_db(":memory:").await.unwrap();

        let [client_1, client_2] = make_synth_tokens();
        let client_1_id = *client_1.token.issuance_id();
        let client_2_id = *client_2.token.issuance_id();

        insert_open_event(&conn, &client_1, 0).await.unwrap();
        insert_open_event(&conn, &client_2, 0).await.unwrap();

        insert_keyserve_event(&conn, client_1_id, 100)
            .await
            .unwrap();

        // insert an event outside the last 24h, should be ignored
        insert_keyserve_event_at_time(&conn, client_2_id, 1000, now_utc() - 200_000)
            .await
            .unwrap();

        insert_keyserve_event(&conn, client_2_id, 50).await.unwrap();

        insert_keyserve_event(&conn, client_1_id, 150)
            .await
            .unwrap();

        assert_eq!(
            query_client_keyserved_bp_last_day(&conn, client_1_id)
                .await
                .unwrap(),
            250
        );
        assert_eq!(
            query_client_keyserved_bp_last_day(&conn, client_2_id)
                .await
                .unwrap(),
            50
        );
    }

    #[tokio::test]
    async fn insert_exceedance() {
        let conn = open_db(":memory:").await.unwrap();

        let certs = scep_client_helpers::certs::ClientCerts::load_test_certs();
        let client_token = certs.token;
        let client_mid = *client_token.token.issuance_id();

        insert_open_event(&conn, &client_token, 0).await.unwrap();
        insert_ratelimit_exceedance(&conn, client_mid, 100)
            .await
            .unwrap();

        let (saved_id, saved_amt): (SqlCertificateId, u64) = conn
            .call(|conn| {
                Ok(conn
                    .query_row(
                        "SELECT client_mid, attempted_bp FROM ratelimit_exceedances",
                        params![],
                        |row| Ok((row.get_unwrap(0), row.get_unwrap(1))),
                    )
                    .unwrap())
            })
            .await
            .unwrap();

        assert_eq!(saved_id.0, client_mid);
        assert_eq!(saved_amt, 100);
    }
}
