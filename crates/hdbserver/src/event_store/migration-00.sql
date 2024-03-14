-- Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
-- SPDX-License-Identifier: MIT OR Apache-2.0

CREATE TABLE open_events(
    open_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    protocol_version INTEGER NOT NULL,
    timestamp_utc INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_open_events_timestamp_utc ON open_events(timestamp_utc);

CREATE TABLE screen_events(
    screen_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    screened_bp INTEGER NOT NULL,
    region TEXT NOT NULL,
    timestamp_utc INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_screen_events_timestamp_utc ON screen_events(timestamp_utc);

CREATE TABLE screen_results(
    result_id INTEGER PRIMARY KEY,
    screen_id INTEGER NOT NULL,
    synthesis_permission TEXT NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    FOREIGN KEY (screen_id) REFERENCES screen_events(screen_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE ratelimit_exceedances(
    exceedance_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    client_cert_chain BLOB NOT NULL,
    attempted_bp INTEGER NOT NULL,
    timestamp_utc INTEGER NOT NULL
) STRICT;