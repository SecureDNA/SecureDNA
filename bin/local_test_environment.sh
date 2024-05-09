#!/usr/bin/env bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

# Spins up an "uncontainerized" local test environment that parallels docker-compose.yml:
# - HDB server at localhost:5300
# - Keyservers at localhost:5301-5303
# - Synthclient API at localhost:80
#
# Note that this expects to be run from the repo root, not from inside bin/

# Terminate child processes when this one is terminated.
trap 'kill 0' EXIT

cargo=cargo
profile="${1:-release-with-debug}"

# On WSL, use `cargo.exe` if `cargo` does not exist.
if [ -f /proc/sys/fs/binfmt_misc/WSLInterop ] && ! command -v cargo; then
    cargo=cargo.exe
fi

# Build everything first
$cargo build --profile "$profile" --bin hdbserver --bin keyserver --bin synthclient

$cargo run --profile "$profile" --bin hdbserver -- --cfg-path test/cfg/database.toml &

$cargo run --profile "$profile" --bin keyserver -- --cfg-path test/cfg/keyserver1.toml &

$cargo run --profile "$profile" --bin keyserver -- --cfg-path test/cfg/keyserver2.toml &

$cargo run --profile "$profile" --bin keyserver -- --cfg-path test/cfg/keyserver3.toml &

sleep 5
$cargo run --profile "$profile" --bin synthclient -- \
    --port 80 \
    --hdb-domains db1.localhost.securedna.org:5300 \
    --keyserver-domains ks1.localhost.securedna.org:5301,ks2.localhost.securedna.org:5302,ks3.localhost.securedna.org:5303 \
    --use-http \
    --use-test-roots-do-not-use-this-in-prod \
    --token-file test/certs/synthesizer-token.st \
    --keypair-file test/certs/synthesizer-token.priv \
    --keypair-passphrase-file test/certs/synthesizer-passphrase.txt &

wait
