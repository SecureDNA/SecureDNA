-- Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
-- SPDX-License-Identifier: MIT OR Apache-2.0

CREATE TABLE servers(
    domain TEXT PRIMARY KEY UNIQUE NOT NULL,
    server_version INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_servers_domain ON servers(domain);
