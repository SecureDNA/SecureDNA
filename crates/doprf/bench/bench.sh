#!/usr/bin/env bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

# requires `flamegraph`: cargo install flamegraph
# .....and `hyperfine`:  cargo install hyperfine

# kill children on exit
# shellcheck disable=SC2064
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT
# cd to bench directory
cd "$(dirname "${BASH_SOURCE[0]}")" || exit

# this script just benchmarks the hash server, so this is only used to build the hdb
# it was also used to build queryset.dat, so that would need to be rebuilt if it changes
# This is only an arbitrary test key
SECRET_KEY=8ede15e780a81f089568e0875b62313badd473e3fb062311b5721bb8da3f3e00

mkdir -p hdb_database
../target/release/genhdb "$SECRET_KEY" ./hazards.fragset ./hdb_database

flamegraph ../target/release/hdbserver ./hdb_database --port 3000 &

sleep 5  # give the server time to boot

hyperfine 'curl --data-binary "@queryset.dat" --header "Content-Type: application/x-hdb-queryset" "localhost:3000/q"'
