-- Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
-- SPDX-License-Identifier: MIT OR Apache-2.0

CREATE TABLE certs(
    client_mid BLOB NOT NULL PRIMARY KEY CHECK(length(client_mid) = 16),
    client_token BLOB NOT NULL
) STRICT;

CREATE INDEX idx_certs_client_mid ON certs(client_mid);

CREATE TABLE open_events(
    open_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    protocol_version INTEGER NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    FOREIGN KEY (client_mid) REFERENCES certs(client_mid) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_open_events_client_mid ON open_events(client_mid);
CREATE INDEX idx_open_events_timestamp_utc ON open_events(timestamp_utc);

CREATE TABLE keyserve_events(
    keyserve_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    keyserved_bp INTEGER NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    FOREIGN KEY (client_mid) REFERENCES certs(client_mid) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_keyserve_events_client_mid ON keyserve_events(client_mid);
CREATE INDEX idx_keyserve_events_timestamp_utc ON keyserve_events(timestamp_utc);

CREATE TABLE ratelimit_exceedances(
    exceedance_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    attempted_bp INTEGER NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    FOREIGN KEY (client_mid) REFERENCES certs(client_mid) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_ratelimit_exceedances_client_mid ON ratelimit_exceedances(client_mid);