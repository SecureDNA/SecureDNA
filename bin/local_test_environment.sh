#!/usr/bin/env bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

# Spins up an "uncontainerized" local test environment that parallels docker-compose.yml:
# - HDB server at localhost:5300
# - Keyservers at localhost:5301-5303
# - Synthclient API at localhost:80

# Terminate child processes when this one is terminated.
trap 'kill 0' EXIT

cargo=cargo

# On WSL, use `cargo.exe` if `cargo` does not exist.
if [ -f /proc/sys/fs/binfmt_misc/WSLInterop ] && ! command -v cargo; then
    cargo=cargo.exe
fi

# Build everything first
$cargo build --profile release-with-debug --bin hdbserver --bin keyserver --bin synthclient

$cargo run --profile release-with-debug --bin hdbserver -- --port 5300 ./test/data/hdb \
    --manufacturer-roots test/certs/manufacturer_roots \
    --token-file test/certs/database-token.dt \
    --keypair-file test/certs/database-token.priv \
    --keypair-passphrase-file test/certs/database-passphrase.txt \
    --allow-insecure-cookie &

$cargo run --profile release-with-debug --bin keyserver -- --port 5301 --keyshare "$SECUREDNA_KEYSERVER_KEYSHARE_1" --id 1 \
    --active-security-key "$SECUREDNA_KEYSERVER_ACTIVE_SECURITY_KEY" \
    --keyholders-required 3 \
    --manufacturer-roots test/certs/manufacturer_roots \
    --token-file test/certs/keyserver-token-1.kt \
    --keypair-file test/certs/keyserver-token-1.priv \
    --keypair-passphrase-file test/certs/keyserver-passphrase.txt \
    --allow-insecure-cookie &

$cargo run --profile release-with-debug --bin keyserver -- --port 5302 --keyshare "$SECUREDNA_KEYSERVER_KEYSHARE_2" --id 2 \
    --active-security-key "$SECUREDNA_KEYSERVER_ACTIVE_SECURITY_KEY" \
    --keyholders-required 3 \
    --manufacturer-roots test/certs/manufacturer_roots \
    --token-file test/certs/keyserver-token-2.kt \
    --keypair-file test/certs/keyserver-token-2.priv \
    --keypair-passphrase-file test/certs/keyserver-passphrase.txt \
    --allow-insecure-cookie &

$cargo run --profile release-with-debug --bin keyserver -- --port 5303 --keyshare "$SECUREDNA_KEYSERVER_KEYSHARE_3" --id 3 \
    --active-security-key "$SECUREDNA_KEYSERVER_ACTIVE_SECURITY_KEY" \
    --keyholders-required 3 \
    --manufacturer-roots test/certs/manufacturer_roots \
    --token-file test/certs/keyserver-token-3.kt \
    --keypair-file test/certs/keyserver-token-3.priv \
    --keypair-passphrase-file test/certs/keyserver-passphrase.txt \
    --allow-insecure-cookie &

sleep 5
$cargo run --profile release-with-debug --bin synthclient -- \
    --port 80 \
    --hdb-domains db1.localhost.securedna.org:5300 \
    --keyserver-domains ks1.localhost.securedna.org:5301,ks2.localhost.securedna.org:5302,ks3.localhost.securedna.org:5303 \
    --use-http \
    --use-test-roots-do-not-use-this-in-prod \
    --token-file test/certs/synthesizer-token.st \
    --keypair-file test/certs/synthesizer-token.priv \
    --keypair-passphrase-file test/certs/synthesizer-passphrase.txt &

wait
