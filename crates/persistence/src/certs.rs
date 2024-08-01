// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Connection, SqlCertificateId};
use certificates::{Id, SynthesizerTokenGroup, TokenBundle};
use rusqlite::params;
use std::collections::HashMap;
use tracing::warn;

pub async fn query_certs(
    conn: &Connection,
) -> Result<HashMap<Id, TokenBundle<SynthesizerTokenGroup>>, tokio_rusqlite::Error> {
    conn.call(move |conn| {
        let mut stmt = conn.prepare("SELECT client_mid, client_token FROM certs")?;
        let rows = stmt.query_map(params![], |row| {
            Ok((row.get::<_, SqlCertificateId>(0)?.0, row.get(1)?))
        })?;

        let mut result = HashMap::new();
        let mut invalid_count = 0;

        for row in rows {
            let (client_mid, client_token_bytes): (Id, Vec<u8>) = row?;
            match TokenBundle::<SynthesizerTokenGroup>::from_file_contents(client_token_bytes) {
                Ok(token_bundle) => {
                    result.insert(client_mid, token_bundle);
                }
                Err(_) => {
                    invalid_count += 1;
                }
            }
        }

        if invalid_count > 0 {
            warn!("Found {} invalid certs", invalid_count);
        }

        Ok(result)
    })
    .await
}

pub mod test_utils {
    use certificates::Issued;

    use super::*;
    use crate::open_events;
    use crate::open_events::test_utils::make_synth_tokens;

    pub async fn test_query_certs(conn: Connection) {
        let [client_token_1, client_token_2] = make_synth_tokens();

        open_events::insert_open_event(&conn, &client_token_1, 0)
            .await
            .unwrap();
        open_events::insert_open_event(&conn, &client_token_2, 0)
            .await
            .unwrap();

        let certs = query_certs(&conn).await.unwrap();
        assert_eq!(certs.len(), 2);
        assert!(certs.contains_key(client_token_1.token.issuance_id()));
        assert!(certs.contains_key(client_token_2.token.issuance_id()));
    }

    pub async fn test_query_certs_with_invalid_cert(conn: Connection) {
        let [client_token_1, _] = make_synth_tokens();

        open_events::insert_open_event(&conn, &client_token_1, 0)
            .await
            .unwrap();

        conn.call(|conn| {
            conn.execute(
                "INSERT INTO certs (client_mid, client_token) VALUES (?1, ?2)",
                params![
                    SqlCertificateId(Id::new_random()),
                    "invalid_cert".as_bytes()
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let certs = query_certs(&conn).await.unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs.contains_key(client_token_1.token.issuance_id()));
    }
}
