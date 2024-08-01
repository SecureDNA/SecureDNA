// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared certs / open_events logic

use rusqlite::OptionalExtension;
use tokio_rusqlite::{params, Connection};
use tracing::error;

use certificates::{Id, Issued, SynthesizerTokenGroup, TokenBundle};

use crate::{SqlCertificateId, SqlOffsetDateTime};

/// Insert an open event for a new connection, and add the client token to the known-certs
/// table if it hasn't been seen before.
pub async fn insert_open_event(
    conn: &Connection,
    client_token: &TokenBundle<SynthesizerTokenGroup>,
    protocol_version: u64,
) -> Result<(), tokio_rusqlite::Error> {
    let client_mid = *client_token.token.issuance_id();
    let client_token = match client_token.to_file_contents() {
        Ok(s) => s,
        Err(e) => {
            // we always want to insert something for the client_mid so FKs in other tables
            // will be valid, so don't return an error
            //
            // not sure if this branch is even really possible--we've just decoded this
            // cert, so it should only produce an error on re-encode if there's a bug
            // in the certs library afaik
            error!("ratelimit exceeded by invalid certificate for {client_mid}: {e}");
            format!("invalid_cert::{client_mid}::{e}")
        }
    };
    conn.call(move |conn| {
        let tx = conn.transaction()?;

        // insert into certs table if this is a new cert
        tx.execute(
            r#"
            INSERT OR IGNORE INTO certs (client_mid, client_token)
            VALUES (?1, ?2);
            "#,
            params![SqlCertificateId(client_mid), client_token.as_bytes()],
        )?;

        tx.execute(
            r#"
            INSERT INTO open_events (client_mid, protocol_version, timestamp_utc)
            VALUES (?1, ?2, ?3);
            "#,
            params![
                SqlCertificateId(client_mid),
                protocol_version,
                SqlOffsetDateTime::now_utc()
            ],
        )?;

        tx.commit()?;
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

pub mod test_utils {
    //! Exported tests so crates that use these utils can test that they pass with
    //! their migration set.

    use certificates::Builder;
    use certificates::CertificateBundle;
    use std::time::Duration;

    use super::*;

    pub async fn test_open_and_last_version(conn: Connection) {
        let [client_1, client_2] = make_synth_tokens();
        let client_1_id = *client_1.token.issuance_id();
        let client_2_id = *client_2.token.issuance_id();

        insert_open_event(&conn, &client_1, 0).await.unwrap();
        insert_open_event(&conn, &client_2, 1).await.unwrap();
        assert_eq!(
            last_protocol_version_for_client(&conn, client_1_id)
                .await
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            last_protocol_version_for_client(&conn, client_2_id)
                .await
                .unwrap(),
            Some(1)
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        insert_open_event(&conn, &client_1, 1).await.unwrap();
        insert_open_event(&conn, &client_2, 2).await.unwrap();
        assert_eq!(
            last_protocol_version_for_client(&conn, client_1_id)
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            last_protocol_version_for_client(&conn, client_2_id)
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

    pub async fn test_open_inserts_single_cert(conn: Connection) {
        let [client_token, _] = make_synth_tokens();
        let client_mid = *client_token.token.issuance_id();

        insert_open_event(&conn, &client_token, 0).await.unwrap();
        // shouldn't insert a second cert
        insert_open_event(&conn, &client_token, 0).await.unwrap();

        let (saved_id, saved_token): (SqlCertificateId, Vec<u8>) = conn
            .call(|conn| {
                // query_row since there should only be a single row in certs
                Ok(conn
                    .query_row(
                        "SELECT client_mid, client_token FROM certs;",
                        params![],
                        |row| Ok((row.get_unwrap(0), row.get_unwrap(1))),
                    )
                    .unwrap())
            })
            .await
            .unwrap();

        assert_eq!(saved_id.0, client_mid);
        assert!(TokenBundle::<SynthesizerTokenGroup>::from_file_contents(saved_token).is_ok());
    }

    /// Helper to generate some synthesizer tokens for testing
    pub fn make_synth_tokens<const N: usize>() -> [TokenBundle<SynthesizerTokenGroup>; N] {
        use certificates as c;
        // make manufacturer root
        let manu_root_keypair = c::KeyPair::new_random();
        let manu_root_cert =
            c::RequestBuilder::<c::Manufacturer>::root_v1_builder(manu_root_keypair.public_key())
                .build()
                .load_key(manu_root_keypair.clone())
                .unwrap()
                .self_sign(c::IssuerAdditionalFields::default())
                .unwrap();

        let manu_root_bundle = CertificateBundle::new(manu_root_cert, None);

        // make manufacturer intermediate
        let manu_inter_keypair = c::KeyPair::new_random();
        let manu_inter_cert_req = c::RequestBuilder::<c::Manufacturer>::intermediate_v1_builder(
            manu_inter_keypair.public_key(),
        )
        .build();
        let manu_inter_bundle = manu_root_bundle
            .issue_cert_bundle(
                manu_inter_cert_req,
                c::IssuerAdditionalFields {
                    expiration: c::Expiration::expiring_in_days(60).unwrap(),
                    emails_to_notify: vec![],
                },
                manu_root_keypair.clone(),
            )
            .unwrap();

        // make manufacturer leaf
        let manu_leaf_keypair = c::KeyPair::new_random();
        let manu_leaf_cert_req =
            c::RequestBuilder::<c::Manufacturer>::leaf_v1_builder(manu_leaf_keypair.public_key())
                .build();
        let manu_leaf_bundle = manu_inter_bundle
            .issue_cert_bundle(
                manu_leaf_cert_req,
                c::IssuerAdditionalFields {
                    expiration: c::Expiration::expiring_in_days(60).unwrap(),
                    emails_to_notify: vec![],
                },
                manu_inter_keypair.clone(),
            )
            .unwrap();

        // make synthesizer tokens
        std::array::from_fn(|_| {
            let synth_keypair = c::KeyPair::new_random();
            let synth_req = c::SynthesizerTokenRequest::v1_token_request(
                synth_keypair.public_key(),
                "example.com",
                "synthesizer mcsynthface",
                "1337",
                1_000,
                None,
            );
            manu_leaf_bundle
                .issue_synthesizer_token_bundle(
                    synth_req,
                    c::Expiration::expiring_in_days(60).unwrap(),
                    manu_leaf_keypair.clone(),
                )
                .unwrap()
        })
    }
}
