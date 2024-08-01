// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use certificates::{ExemptionTokenGroup, Id, Issued, TokenBundle};
pub use persistence::{
    certs::query_certs,
    open_events::{insert_open_event, last_protocol_version_for_client},
    statistics::query_exceedances_per_day_per_client,
    Connection,
};
use persistence::{
    params,
    rusqlite::{self, types::ToSqlOutput, ToSql},
    tokio_rusqlite::{self, OptionalExtension},
    Migrations, OpenError, SqlCertificateId, SqlOffsetDateTime, SqlRegion, SqlSynthesisPermission,
    M,
};
use shared_types::{
    et::WithOtps,
    synthesis_permission::{Region, SynthesisPermission},
};
use tracing::warn;

pub async fn open_db(path: impl AsRef<Path>) -> Result<Connection, OpenError> {
    persistence::open_db(
        path,
        // do not modify these migrations, instead create a new migration
        Migrations::from_iter([
            M::up(include_str!("migration-00.sql")),
            M::up(include_str!("migration-01.sql")),
        ]),
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenEventId(i64);

impl ToSql for ScreenEventId {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

pub async fn insert_screen_event(
    conn: &Connection,
    client_mid: Id,
    screened_bp: u64,
    region: Region,
    ets: &[WithOtps<TokenBundle<ExemptionTokenGroup>>],
) -> Result<ScreenEventId, tokio_rusqlite::Error> {
    insert_screen_event_at_time(
        conn,
        client_mid,
        screened_bp,
        region,
        ets,
        SqlOffsetDateTime::now_utc(),
    )
    .await
}

async fn insert_screen_event_at_time(
    conn: &Connection,
    client_mid: Id,
    screened_bp: u64,
    region: Region,
    ets: &[WithOtps<TokenBundle<ExemptionTokenGroup>>],
    timestamp_utc: impl Into<SqlOffsetDateTime>,
) -> Result<ScreenEventId, tokio_rusqlite::Error> {
    let timestamp_utc = timestamp_utc.into();
    let et_data: Result<Vec<_>, _> = ets
        .iter()
        .map(|et| match et.et.to_wire_format() {
            Ok(der) => Ok((SqlCertificateId(*et.et.token.issuance_id()), der)),
            Err(e) => Err(tokio_rusqlite::Error::Other(e.into())),
        })
        .collect();
    let et_data = et_data?;

    let id = conn
        .call(move |conn| {
            let tx = conn.transaction()?;

            let mut elt_der_sha256s: Vec<u8> = vec![];

            for (id, der) in et_data {
                use sha2::{Sha256, Digest};
                let der_sha256: [u8; 32] = Sha256::digest(&der).into();

                let old_hash: Option<[u8; 32]> =
                    tx.prepare("SELECT der_sha256 FROM elts WHERE issuance_id = ?1")?
                        .query_row(params![id], |row| row.get(0))
                        .optional()?;
                if let Some(old_hash) = old_hash {
                    if old_hash != der_sha256 {
                        warn!("WARNING: Event store contains two exemption tokens with issuance_id {} but different SHA-256 hashes. (issuance_id should be unique; has the token been spoofed?)", id.0);
                    }
                }

                tx.execute(
                    r#"INSERT OR IGNORE INTO elts (der_sha256, issuance_id, der) VALUES (?1, ?2, ?3);"#,
                    params![der_sha256, id, der],
                )?;

                elt_der_sha256s.extend(der_sha256);
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
                    elt_der_sha256s,
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
                SqlOffsetDateTime::now_utc(),
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

pub async fn query_client_screened_bp_in_last_day(
    conn: &Connection,
    client_mid: Id,
) -> Result<u64, tokio_rusqlite::Error> {
    query_client_screened_bp_since(conn, client_mid, SqlOffsetDateTime::one_day_ago_utc()).await
}

pub async fn query_client_screened_bp_since(
    conn: &Connection,
    client_mid: Id,
    timestamp_utc: impl Into<SqlOffsetDateTime>,
) -> Result<u64, tokio_rusqlite::Error> {
    let timestamp_utc = timestamp_utc.into();
    let sum = conn
        .call(move |conn| {
            let sum = conn.query_row(
                r#"
                SELECT COALESCE(SUM(screened_bp), 0)
                FROM screen_events
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
        "screen_events",
        "screened_bp",
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
        "screen_events",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use certificates::{Issued, Organism};
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

        let screen_event = insert_screen_event(&conn, client_1_id, 100, Region::Us, &[])
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
            &[],
            persistence::OffsetDateTime::now_utc() - persistence::Duration::days(10),
        )
        .await
        .unwrap();

        insert_screen_event(&conn, client_2_id, 50, Region::All, &[])
            .await
            .unwrap();

        let screen_event = insert_screen_event(&conn, client_1_id, 150, Region::Eu, &[])
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

        // Two insertions with the same exemption token:
        let et = WithOtps {
            et: hdb::exemption::make_test_et(vec![]),
            requestor_otp: "test".to_owned(),
            issuer_otp: None,
        };
        let ets = &[et];

        insert_screen_event(&conn, client_1_id, 333, Region::Us, ets)
            .await
            .unwrap();
        insert_screen_event(&conn, client_1_id, 444, Region::Us, ets)
            .await
            .unwrap();

        // Verify that the exemption token is in `ets` only once.
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

        let et_id = SqlCertificateId(*ets[0].et.token.issuance_id());
        let elt_der = ets[0].et.to_wire_format().unwrap();
        assert_eq!(results, vec![(et_id, elt_der)]);
    }

    #[tokio::test]
    async fn insert_multiple_elts() {
        let conn = open_db(":memory:").await.unwrap();

        let [client_1] = make_synth_tokens();
        let client_1_id = *client_1.token.issuance_id();

        insert_open_event(&conn, &client_1, 0).await.unwrap();

        // Insertion with two exemption tokens:
        let et1 = WithOtps {
            et: hdb::exemption::make_test_et(vec![]),
            requestor_otp: "test".to_owned(),
            issuer_otp: None,
        };
        let org = Organism {
            name: "test_organism".to_owned(),
            sequences: vec![],
        };
        let et2 = WithOtps {
            et: hdb::exemption::make_test_et(vec![org]),
            requestor_otp: "test".to_owned(),
            issuer_otp: None,
        };
        let ets = &[et1, et2];

        let screen_id = insert_screen_event(&conn, client_1_id, 123, Region::Us, ets)
            .await
            .unwrap();

        let der_sha256: Vec<u8> = conn
            .call_unwrap(move |conn| {
                conn.query_row(
                    "SELECT elt_der_sha256 FROM screen_events WHERE screen_id = ?1",
                    params![screen_id],
                    |r| r.get(0),
                )
            })
            .await
            .unwrap();

        // We should see two hashes in the exemption token table...
        let results: Vec<(SqlCertificateId, Vec<u8>)> = conn
            .call(|conn| {
                Ok(conn
                    .prepare("SELECT issuance_id, der_sha256 FROM elts")?
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .map(|x| x.unwrap())
                    .collect())
            })
            .await
            .unwrap();

        assert_eq!(results.len(), 2);

        // And the elt_der_sha256 should be 2*32 bytes.
        assert_eq!(der_sha256.len(), 2 * 32);

        // It should be the concatenation of the individual exemption token hashes.
        let halves = (&der_sha256[..32], &der_sha256[32..]);
        let h0 = results[0].1.as_slice();
        let h1 = results[1].1.as_slice();
        assert!(halves == (h0, h1) || halves == (h1, h0));
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

        let et = &[];

        insert_open_event(&conn, &client_1, 0).await.unwrap();
        insert_open_event(&conn, &client_2, 0).await.unwrap();

        // Insert screen events for client_1
        let client_1_evt_0_bp = 1000;
        let event = insert_screen_event_at_time(
            &conn,
            client_1_id,
            client_1_evt_0_bp,
            Region::Us,
            et,
            date,
        )
        .await
        .unwrap();
        insert_screen_result(&conn, event, SynthesisPermission::Granted)
            .await
            .unwrap();

        let client_1_evt_1_bp = 2000;
        let event = insert_screen_event_at_time(
            &conn,
            client_1_id,
            client_1_evt_1_bp,
            Region::Eu,
            et,
            date_1,
        )
        .await
        .unwrap();
        insert_screen_result(&conn, event, SynthesisPermission::Denied)
            .await
            .unwrap();

        let client_1_evt_2_bp = 2000;
        let event = insert_screen_event_at_time(
            &conn,
            client_1_id,
            client_1_evt_2_bp,
            Region::Eu,
            et,
            date_1 + persistence::Duration::hours(2),
        )
        .await
        .unwrap();
        insert_screen_result(&conn, event, SynthesisPermission::Denied)
            .await
            .unwrap();

        // Insert screen events for client_2
        let client_2_evt_0_bp = 1500;
        let event = insert_screen_event_at_time(
            &conn,
            client_2_id,
            client_2_evt_0_bp,
            Region::All,
            et,
            date,
        )
        .await
        .unwrap();
        insert_screen_result(&conn, event, SynthesisPermission::Granted)
            .await
            .unwrap();

        let client_2_evt_1_bp = 3000;
        let event = insert_screen_event_at_time(
            &conn,
            client_2_id,
            client_2_evt_1_bp,
            Region::Us,
            et,
            date_2,
        )
        .await
        .unwrap();
        insert_screen_result(&conn, event, SynthesisPermission::Granted)
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
        assert_eq!(bp_per_day[0], (date.into(), client_1_id, client_1_evt_0_bp));
        assert_eq!(bp_per_day[1], (date.into(), client_2_id, client_2_evt_0_bp));
        assert_eq!(
            bp_per_day[2],
            (
                date_1.into(),
                client_1_id,
                client_1_evt_1_bp + client_1_evt_2_bp
            )
        );
        assert_eq!(
            bp_per_day[3],
            (date_2.into(), client_2_id, client_2_evt_1_bp)
        );

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
