-- Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- This migration removes a foreign key from the "screen_events" table:
--
--     FOREIGN KEY (elt_der_sha256) REFERENCES elts(der_sha256) ON DELETE RESTRICT
--
-- A screen event can now have multiple ELTs. The elt_der_sha256 BLOB now has
-- length 32*n where n is the amount of ELTs provided. Each 32-byte chunk is a
-- SHA256 of a row in the "elts" table.
--
-- A query like this will find ELTs used in screen events:
--
--     SELECT * FROM elts e JOIN screen_events s
--     ON instr(s.elt_der_sha256, e.der_sha256)
--     WHERE ...

CREATE TABLE screen_events_new(
    screen_id INTEGER PRIMARY KEY,
    client_mid BLOB NOT NULL CHECK(length(client_mid) = 16),
    screened_bp INTEGER NOT NULL,
    region TEXT NOT NULL,
    timestamp_utc INTEGER NOT NULL,
    elt_der_sha256 BLOB,
    FOREIGN KEY (client_mid) REFERENCES certs(client_mid) ON DELETE RESTRICT
) STRICT;

INSERT INTO screen_events_new SELECT * FROM screen_events;
DROP TABLE screen_events;
ALTER TABLE screen_events_new RENAME TO screen_events;
CREATE INDEX idx_screen_events_client_mid ON screen_events(client_mid);
CREATE INDEX idx_screen_events_timestamp_utc ON screen_events(timestamp_utc);
