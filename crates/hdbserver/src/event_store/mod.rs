// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use certificates::{ExemptionListTokenGroup, Id, Issued, TokenBundle};
use persistence::{
    now_utc, one_day_ago_utc, params, tokio_rusqlite, tokio_rusqlite::OptionalExtension,
    Migrations, OpenError, SqlCertificateId, SqlRegion, SqlSynthesisPermission, M,
};
pub use persistence::{
    open_events::{insert_open_event, last_protocol_version_for_client},
    Connection,
};
use shared_types::synthesis_permission::{Region, SynthesisPermission};
use tracing::warn;

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

pub async fn insert_screen_event(
    conn: &Connection,
    client_mid: Id,
    screened_bp: u64,
    region: Region,
    elt: Option<&TokenBundle<ExemptionListTokenGroup>>,
) -> Result<ScreenEventId, tokio_rusqlite::Error> {
    insert_screen_event_at_time(conn, client_mid, screened_bp, region, elt, now_utc()).await
}

async fn insert_screen_event_at_time(
    conn: &Connection,
    client_mid: Id,
    screened_bp: u64,
    region: Region,
    elt: Option<&TokenBundle<ExemptionListTokenGroup>>,
    timestamp_utc: i64,
) -> Result<ScreenEventId, tokio_rusqlite::Error> {
    let elt_data = match elt {
        None => None,
        Some(elt) => match elt.to_wire_format() {
            Ok(der) => Some((SqlCertificateId(*elt.token.issuance_id()), der)),
            Err(e) => return Err(tokio_rusqlite::Error::Other(e.into())),
        },
    };

    let id = conn
        .call(move |conn| {
            let tx = conn.transaction()?;

            let elt_der_sha256 = match elt_data {
                None => None,
                Some((id, der)) => {
                    use sha2::{Sha256, Digest};
                    let der_sha256: [u8; 32] = Sha256::digest(&der).into();

                    let old_hash: Option<[u8; 32]> =
                        tx.prepare("SELECT der_sha256 FROM elts WHERE issuance_id = ?1")?
                            .query_row(params![id], |row| row.get(0))
                            .optional()?;
                    if let Some(old_hash) = old_hash {
                        if old_hash != der_sha256 {
                            warn!("WARNING: Event store contains two ELTs with issuance_id {} but different SHA-256 hashes. (issuance_id should be unique; has the ELT been spoofed?)", id.0);
                        }
                    }

                    tx.execute(
                        r#"INSERT OR IGNORE INTO elts (der_sha256, issuance_id, der) VALUES (?1, ?2, ?3);"#,
                        params![der_sha256, id, der],
                    )?;
                    Some(der_sha256)
                }
            };

            tx.execute(
                r#"
                INSERT INTO screen_events (client_mid, screened_bp, region, timestamp_utc, elt_der_sha256)
                VALUES (?1, ?2, ?3, ?4, ?5);
                "#,
                params![
                    SqlCertificateId(client_mid),
                    screened_bp,
                    SqlRegion(region),
                    timestamp_utc,
                    elt_der_sha256,
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

pub async fn query_client_screened_bp_in_last_day(
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
    async fn open_inserts_single_cert() {
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

        let screen_event = insert_screen_event(&conn, client_1_id, 100, Region::Us, None)
            .await
            .unwrap();
        insert_screen_result(&conn, screen_event, SynthesisPermission::Granted)
            .await
            .unwrap();

        // insert an event outside the last 24h, should be ignored
        insert_screen_event_at_time(
            &conn,
            client_2_id,
            1000,
            Region::All,
            None,
            now_utc() - 200_000,
        )
        .await
        .unwrap();

        insert_screen_event(&conn, client_2_id, 50, Region::All, None)
            .await
            .unwrap();

        let screen_event = insert_screen_event(&conn, client_1_id, 150, Region::Eu, None)
            .await
            .unwrap();
        insert_screen_result(&conn, screen_event, SynthesisPermission::Denied)
            .await
            .unwrap();

        assert_eq!(
            query_client_screened_bp_in_last_day(&conn, client_1_id)
                .await
                .unwrap(),
            250
        );
        assert_eq!(
            query_client_screened_bp_in_last_day(&conn, client_2_id)
                .await
                .unwrap(),
            50
        );

        // Two insertions with the same ELT:
        let elt = hdb::exemption::make_test_elt(vec![]);

        insert_screen_event(&conn, client_1_id, 333, Region::Us, Some(&elt))
            .await
            .unwrap();
        insert_screen_event(&conn, client_1_id, 444, Region::Us, Some(&elt))
            .await
            .unwrap();

        // Verify that the ELT is in `elts` only once.
        let results: Vec<(SqlCertificateId, Vec<u8>)> = conn
            .call(|conn| {
                Ok(conn
                    .prepare("SELECT issuance_id, der FROM elts")?
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .map(|x| x.unwrap())
                    .collect())
            })
            .await
            .unwrap();

        let elt_id = SqlCertificateId(*elt.token.issuance_id());
        let elt_der = elt.to_wire_format().unwrap();
        assert_eq!(results, vec![(elt_id, elt_der)]);
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
