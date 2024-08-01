// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use certificates::Id;
pub use persistence::{
    certs::query_certs,
    open_events::{insert_open_event, last_protocol_version_for_client},
    statistics::query_exceedances_per_day_per_client,
    Connection,
};
use persistence::{
    params, tokio_rusqlite, Migrations, OpenError, SqlCertificateId, SqlOffsetDateTime, M,
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
    insert_keyserve_event_at_time(conn, client_mid, keyserve_bp, SqlOffsetDateTime::now_utc()).await
}

async fn insert_keyserve_event_at_time(
    conn: &Connection,
    client_mid: Id,
    keyserve_bp: u64,
    timestamp_utc: impl Into<SqlOffsetDateTime>,
) -> Result<(), tokio_rusqlite::Error> {
    let timestamp_utc = timestamp_utc.into();
    conn.call(move |conn| {
        conn.execute(
            r#"
                INSERT INTO keyserve_events (client_mid, keyserved_bp, timestamp_utc)
                VALUES (?1, ?2, ?3);
                "#,
            params![SqlCertificateId(client_mid), keyserve_bp, timestamp_utc],
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
    insert_ratelimit_exceedance_at_time(
        conn,
        client_mid,
        attempted_bp,
        SqlOffsetDateTime::now_utc(),
    )
    .await
}

pub async fn insert_ratelimit_exceedance_at_time(
    conn: &Connection,
    client_mid: Id,
    attempted_bp: u64,
    timestamp_utc: impl Into<SqlOffsetDateTime>,
) -> Result<(), tokio_rusqlite::Error> {
    let timestamp_utc = timestamp_utc.into();
    conn.call(move |conn| {
        conn.execute(
            r#"
            INSERT INTO ratelimit_exceedances (client_mid, attempted_bp, timestamp_utc)
            VALUES (?1, ?2, ?3);
            "#,
            params![SqlCertificateId(client_mid), attempted_bp, timestamp_utc],
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
    query_client_keyserved_bp_since(conn, client_mid, SqlOffsetDateTime::one_day_ago_utc()).await
}

pub async fn query_client_keyserved_bp_since(
    conn: &Connection,
    client_mid: Id,
    timestamp_utc: impl Into<SqlOffsetDateTime>,
) -> Result<u64, tokio_rusqlite::Error> {
    let timestamp_utc = timestamp_utc.into();
    let sum = conn
        .call(move |conn| {
            let sum = conn.query_row(
                r#"
                SELECT COALESCE(SUM(keyserved_bp), 0)
                FROM keyserve_events
                WHERE client_mid = ?1 AND timestamp_utc >= ?2;
                "#,
                params![SqlCertificateId(client_mid), timestamp_utc],
                |row| row.get(0),
            )?;
            Ok(sum)
        })
        .await?;
    Ok(sum)
}

pub async fn query_bp_per_day_per_client(
    conn: &Connection,
    start_date: impl Into<SqlOffsetDateTime>,
    end_date: impl Into<SqlOffsetDateTime>,
) -> Result<Vec<(SqlOffsetDateTime, Id, u64)>, tokio_rusqlite::Error> {
    persistence::statistics::query_bp_per_day_per_client(
        conn,
        start_date,
        end_date,
        "keyserve_events",
        "keyserved_bp",
    )
    .await
}

pub async fn query_orders_per_day_per_client(
    conn: &Connection,
    start_date: impl Into<SqlOffsetDateTime>,
    end_date: impl Into<SqlOffsetDateTime>,
) -> Result<Vec<(SqlOffsetDateTime, Id, u64)>, tokio_rusqlite::Error> {
    persistence::statistics::query_orders_per_day_per_client(
        conn,
        start_date,
        end_date,
        "keyserve_events",
    )
    .await
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
        insert_keyserve_event_at_time(
            &conn,
            client_2_id,
            1000,
            persistence::OffsetDateTime::now_utc() - persistence::Duration::days(10),
        )
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

    #[tokio::test]
    async fn test_query_certs() {
        let conn = open_db(":memory:").await.unwrap();
        persistence::certs::test_utils::test_query_certs(conn).await;
    }

    #[tokio::test]
    async fn test_query_certs_with_invalid_cert() {
        let conn = open_db(":memory:").await.unwrap();
        persistence::certs::test_utils::test_query_certs_with_invalid_cert(conn).await;
    }

    #[tokio::test]
    async fn test_statistics() {
        let conn = open_db(":memory:").await.unwrap();
        let date = persistence::OffsetDateTime::from_unix_timestamp(1714089600).unwrap(); // 2024-04-25
        let date_1 = date + persistence::Duration::days(1);
        let date_2 = date + persistence::Duration::days(2);
        let date_3 = date + persistence::Duration::days(3);

        let [client_1, client_2] = {
            // make sure client 1 has a smaller id than client 2 so the ordering is consistent between test runs
            let mut tokens = make_synth_tokens();
            if tokens[0].token.issuance_id() > tokens[1].token.issuance_id() {
                tokens.swap(0, 1);
            }
            tokens
        };
        let client_1_id = *client_1.token.issuance_id();
        let client_2_id = *client_2.token.issuance_id();

        insert_open_event(&conn, &client_1, 0).await.unwrap();
        insert_open_event(&conn, &client_2, 0).await.unwrap();

        // Insert keyserve events for client_1
        insert_keyserve_event_at_time(&conn, client_1_id, 1000, date)
            .await
            .unwrap();
        insert_keyserve_event_at_time(&conn, client_1_id, 2000, date_1)
            .await
            .unwrap();
        insert_keyserve_event_at_time(
            &conn,
            client_1_id,
            2000,
            date_1 + persistence::Duration::hours(2),
        )
        .await
        .unwrap();

        // Insert keyserve events for client_2
        insert_keyserve_event_at_time(&conn, client_2_id, 1500, date)
            .await
            .unwrap();
        insert_keyserve_event_at_time(&conn, client_2_id, 3000, date_2)
            .await
            .unwrap();

        // Insert exceedance events for both clients
        insert_ratelimit_exceedance_at_time(&conn, client_1_id, 5000, date)
            .await
            .unwrap();
        insert_ratelimit_exceedance_at_time(&conn, client_2_id, 6000, date)
            .await
            .unwrap();
        insert_ratelimit_exceedance_at_time(&conn, client_1_id, 7000, date_1)
            .await
            .unwrap();

        // Test query_bp_per_day_per_client
        let bp_per_day = query_bp_per_day_per_client(&conn, date, date_3)
            .await
            .unwrap();
        assert_eq!(bp_per_day.len(), 4);
        assert_eq!(bp_per_day[0], (date.into(), client_1_id, 1000));
        assert_eq!(bp_per_day[1], (date.into(), client_2_id, 1500));
        assert_eq!(bp_per_day[2], (date_1.into(), client_1_id, 4000));
        assert_eq!(bp_per_day[3], (date_2.into(), client_2_id, 3000));

        // Test query_orders_per_day_per_client
        let orders_per_day = query_orders_per_day_per_client(&conn, date, date_3)
            .await
            .unwrap();
        assert_eq!(orders_per_day.len(), 4);
        assert_eq!(orders_per_day[0], (date.into(), client_1_id, 1));
        assert_eq!(orders_per_day[1], (date.into(), client_2_id, 1));
        assert_eq!(orders_per_day[2], (date_1.into(), client_1_id, 2));
        assert_eq!(orders_per_day[3], (date_2.into(), client_2_id, 1));

        // Test query_exceedances_per_day_per_client
        let exceedances_per_day = query_exceedances_per_day_per_client(&conn, date, date_3)
            .await
            .unwrap();
        assert_eq!(exceedances_per_day.len(), 3);
        assert!(exceedances_per_day.contains(&(date.into(), client_1_id, 1)));
        assert!(exceedances_per_day.contains(&(date.into(), client_2_id, 1)));
        assert!(exceedances_per_day.contains(&(date_1.into(), client_1_id, 1)));
    }
}
