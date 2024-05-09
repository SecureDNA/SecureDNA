-- Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
-- SPDX-License-Identifier: MIT OR Apache-2.0

CREATE TABLE certs(
    client_mid BLOB NOT NULL PRIMARY KEY CHECK(length(client_mid) = 16),
    client_token BLOB NOT NULL
) STRICT;

CREATE INDEX idx_certs_client_mid ON certs(client_mid);

CREATE TABLE elts(
    der_sha256 BLOB NOT NULL PRIMARY KEY CHECK(length(der_sha256) = 32),
    issuance_id BLOB NOT NULL CHECK(length(issuance_id) = 16),
    der BLOB NOT NULL
) STRICT;

CREATE INDEX idx_elts_der_sha256 ON elts(der_sha256);
CREATE INDEX idx_elts_issuance_id ON elts(issuance_id);

CREATE TABLE open_events(
    open_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    protocol_version INTEGER NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    FOREIGN KEY (client_mid) REFERENCES certs(client_mid) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_open_events_client_mid ON open_events(client_mid);
CREATE INDEX idx_open_events_timestamp_utc ON open_events(timestamp_utc);

CREATE TABLE screen_events(
    screen_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    screened_bp INTEGER NOT NULL,
    region TEXT NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    elt_der_sha256 BLOB,
    FOREIGN KEY (client_mid) REFERENCES certs(client_mid) ON DELETE RESTRICT,
    FOREIGN KEY (elt_der_sha256) REFERENCES elts(der_sha256) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_screen_events_client_mid ON screen_events(client_mid);
CREATE INDEX idx_screen_events_timestamp_utc ON screen_events(timestamp_utc);

CREATE TABLE screen_results(
    result_id INTEGER PRIMARY KEY,
    screen_id INTEGER NOT NULL,
    synthesis_permission TEXT NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    FOREIGN KEY (screen_id) REFERENCES screen_events(screen_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_screen_results_screen_id ON screen_results(screen_id);

CREATE TABLE ratelimit_exceedances(
    exceedance_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    attempted_bp INTEGER NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    FOREIGN KEY (client_mid) REFERENCES certs(client_mid) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_ratelimit_exceedances_client_mid ON ratelimit_exceedances(client_mid);
