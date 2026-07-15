-- Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- This migration adds a table into which audit email attempts are logged.

CREATE TABLE audit_email_events(
    audit_email_id    INTEGER  PRIMARY KEY,
    client_mid        BLOB     NOT NULL CHECK(length(client_mid) = 16),
    timestamp_utc     INTEGER  NOT NULL,
    email_address     TEXT     NOT NULL,
    email_public_key  TEXT     NOT NULL,
    error             TEXT, -- NULL if smtp2go returned OK, else a free-form string describing an error
    FOREIGN KEY (client_mid) REFERENCES certs(client_mid) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_audit_email_events_client_mid ON audit_email_events(client_mid);
CREATE INDEX idx_audit_email_events_timestamp_utc ON audit_email_events(timestamp_utc);
