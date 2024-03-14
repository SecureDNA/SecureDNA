// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use certificates::{Id, Issued, SynthesizerTokenGroup, TokenBundle};
pub use persistence::Connection;
use persistence::{
    now_utc, one_day_ago_utc, params, rusqlite::OptionalExtension, tokio_rusqlite, Migrations,
    OpenError, SqlCertificateId, SqlRegion, SqlSynthesisPermission, M,
};
use shared_types::synthesis_permission::{Region, SynthesisPermission};
use tracing::error;

pub async fn open_db(path: impl AsRef<Path>) -> Result<Connection, OpenError> {
    persistence::open_db(
        path,
        // do not modify these migrations, instead create a new migration
        Migrations::from_iter([M::up(include_str!("migration-00.sql"))]),
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenEventId(i64);

pub async fn insert_open_event(
    conn: &Connection,
    client_mid: Id,
    protocol_version: u64,
) -> Result<(), tokio_rusqlite::Error> {
    conn.call(move |conn| {
        conn.execute(
            r#"
            INSERT INTO open_events (client_mid, protocol_version, timestamp_utc)
            VALUES (?1, ?2, ?3);
            "#,
            params![SqlCertificateId(client_mid), protocol_version, now_utc(),],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn last_protocol_version_for_client(
    conn: &Connection,
    client_mid: Id,
) -> Result<Option<u64>, tokio_rusqlite::Error> {
    let protocol_version = conn
        .call(move |conn| {
            let id = conn
                .query_row(
                    r#"
            SELECT protocol_version FROM open_events
            WHERE client_mid = ?1
            ORDER BY timestamp_utc DESC
            LIMIT 1;
            "#,
                    params![SqlCertificateId(client_mid)],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(id)
        })
        .await?;
    Ok(protocol_version)
}

pub async fn insert_screen_event(
    conn: &Connection,
    client_mid: Id,
    screened_bp: u64,
    region: Region,
) -> Result<ScreenEventId, tokio_rusqlite::Error> {
    insert_screen_event_at_time(conn, client_mid, screened_bp, region, now_utc()).await
}

async fn insert_screen_event_at_time(
    conn: &Connection,
    client_mid: Id,
    screened_bp: u64,
    region: Region,
    timestamp_utc: i64,
) -> Result<ScreenEventId, tokio_rusqlite::Error> {
    let id = conn
        .call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                r#"
                INSERT INTO screen_events (client_mid, screened_bp, region, timestamp_utc)
                VALUES (?1, ?2, ?3, ?4);
                "#,
                params![
                    SqlCertificateId(client_mid),
                    screened_bp,
                    SqlRegion(region),
                    timestamp_utc,
                ],
            )?;
            let last_id = tx.last_insert_rowid();
            tx.commit()?;
            Ok(last_id)
        })
        .await?;

    Ok(ScreenEventId(id))
}

pub async fn insert_screen_result(
    conn: &Connection,
    screen_event: ScreenEventId,
    synthesis_permission: SynthesisPermission,
) -> Result<(), tokio_rusqlite::Error> {
    conn.call(move |conn| {
        conn.execute(
            r#"
            INSERT INTO screen_results (screen_id, synthesis_permission, timestamp_utc)
            VALUES (?1, ?2, ?3);
            "#,
            params![
                screen_event.0,
                SqlSynthesisPermission(synthesis_permission),
                now_utc(),
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn insert_ratelimit_exceedance(
    conn: &Connection,
    client_tokenbundle: &TokenBundle<SynthesizerTokenGroup>,
    attempted_bp: u64,
) -> Result<(), tokio_rusqlite::Error> {
    let client_mid = *client_tokenbundle.token.issuance_id();
    let cert_chain = match client_tokenbundle.to_file_contents() {
        Ok(s) => s,
        Err(e) => {
            error!("ratelimit exceeded by invalid certificate for {client_mid}: {e}");
            format!("invalid({client_mid}):{e}")
        }
    };
    conn.call(move |conn| {
        conn.execute(
            r#"
            INSERT INTO ratelimit_exceedances (client_mid, client_cert_chain, attempted_bp, timestamp_utc)
            VALUES (?1, ?2, ?3, ?4);
            "#,
            params![
                SqlCertificateId(client_mid),
                cert_chain.as_bytes(),
                attempted_bp,
                now_utc(),
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn query_client_screened_bp_last_day(
    conn: &Connection,
    client_mid: Id,
) -> Result<u64, tokio_rusqlite::Error> {
    let sum = conn
        .call(move |conn| {
            let sum = conn.query_row(
                r#"
                SELECT COALESCE(SUM(screened_bp), 0)
                FROM screen_events
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
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn open_and_last_version() {
        let conn = open_db(":memory:").await.unwrap();

        let client_1 = Id::new_random();
        let client_2 = Id::new_random();

        insert_open_event(&conn, client_1, 0).await.unwrap();
        insert_open_event(&conn, client_2, 1).await.unwrap();
        assert_eq!(
            last_protocol_version_for_client(&conn, client_1)
                .await
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            last_protocol_version_for_client(&conn, client_2)
                .await
                .unwrap(),
            Some(1)
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        insert_open_event(&conn, client_1, 1).await.unwrap();
        insert_open_event(&conn, client_2, 2).await.unwrap();
        assert_eq!(
            last_protocol_version_for_client(&conn, client_1)
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            last_protocol_version_for_client(&conn, client_2)
                .await
                .unwrap(),
            Some(2)
        );

        assert_eq!(
            last_protocol_version_for_client(&conn, Id::new_random())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn insert_and_query() {
        let conn = open_db(":memory:").await.unwrap();

        let client_1 = Id::new_random();
        let client_2 = Id::new_random();

        let screen_event = insert_screen_event(&conn, client_1, 100, Region::Us)
            .await
            .unwrap();
        insert_screen_result(&conn, screen_event, SynthesisPermission::Granted)
            .await
            .unwrap();

        // insert an event outside the last 24h, should be ignored
        insert_screen_event_at_time(&conn, client_2, 1000, Region::All, now_utc() - 200_000)
            .await
            .unwrap();

        insert_screen_event(&conn, client_2, 50, Region::All)
            .await
            .unwrap();

        let screen_event = insert_screen_event(&conn, client_1, 150, Region::Eu)
            .await
            .unwrap();
        insert_screen_result(&conn, screen_event, SynthesisPermission::Denied)
            .await
            .unwrap();

        assert_eq!(
            query_client_screened_bp_last_day(&conn, client_1)
                .await
                .unwrap(),
            250
        );
        assert_eq!(
            query_client_screened_bp_last_day(&conn, client_2)
                .await
                .unwrap(),
            50
        );
    }

    #[tokio::test]
    async fn insert_exceedance() {
        let conn = open_db(":memory:").await.unwrap();

        let certs = scep_client_helpers::certs::ClientCerts::load_test_certs();
        let client_tokenbundle = certs.token;
        insert_ratelimit_exceedance(&conn, &client_tokenbundle, 100)
            .await
            .unwrap();

        let (saved_id, saved_cert, saved_amt): (SqlCertificateId, Vec<u8>, u64) = conn
            .call(|conn| {
                Ok(conn.query_row(
            "SELECT client_mid, client_cert_chain, attempted_bp FROM ratelimit_exceedances",
            params![],
            |row| {
           Ok((row.get_unwrap(0), row.get_unwrap(1), row.get_unwrap(2)))
        }).unwrap())
            })
            .await
            .unwrap();

        assert_eq!(saved_id.0, *client_tokenbundle.token.issuance_id());
        assert!(TokenBundle::<SynthesizerTokenGroup>::from_file_contents(saved_cert).is_ok());
        assert_eq!(saved_amt, 100);
    }
}
