# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

# Runs the system using docker in the background, but additionally links test hdb to where the docker-compose.yml expects to find it.
# Necessary if you want to run the system for `just test-system` or any manual testing where you need a real hdb.
run-docker-with-test-hdb:
    #! /usr/bin/env sh
    earthly build +dev
    mkdir ./data
    ln -s --no-target-directory ../test/data/hdb ./data/hdb # no-target-directory prevents recursive linking if ./data/hdb already exists
    ./bin/start_test_environment.sh  # Runs "docker compose up -d".

build-docker:
    earthly build +dev

# Runs all rust tests, excluding system tests
test-rust:
    cargo test --workspace

# Runs system tests only. Requires system w/ test hdb linked, see recipe `run-docker-with-test-data`
test-system:
    cargo test -p system_tests -p awesome_hazard_analyzer --features run_system_tests

# Generates an example json API response (following current documentation example).
# Does not include comments; that would be a bit more involved.
# But this will at least ensure that the structure of the API is correct between changes.
gen-api-json-example:
    cargo run -p synthclient --bin gen_api_json_example

# This command will output a json array of objects w/ info about each run.
# You can pipe to jq to analyze, e.g. `jq 'map(select(.conclusion == "success" and .event == "pull_request")) | map(.headBranch)' | rg 'dependabot/npm' | wc -l`
#
# This is in the justfile because we have needed to check LFS and github action minutes fairly regularly
#
# date arg can do ranges like: ">=2023-07-01"
# useful flags to pass through args:
# - `w` for workflow (e.g. Rust)
# - `L` for limit (can be set in addition `created` flag, default is pretty low)
#
# There's other useful cols to pass through `--json`, but basics are listed here. Enter a wrong col name to get a list of right ones.
gh-runs date *args='':
    gh run list --created "{{date}}" --json conclusion,name,headBranch,event,createdAt,url {{args}}

# Testing here can check if tsgen properly generated type information from rust types
test-demo-gui:
    cd demo_gui && npm ci && npm exec tsc && npm test -- --passWithNoTests

# Note: tsgen is run here.
build-wasm-bindings:
    cargo build -p wasm_bindings

# Takes ghcr package (aka image) name and cutoff date,
# keeps only semver-tagged versions and versions younger than cutoff date, removes the rest.
# For valid image names, check https://github.com/orgs/SecureDNA/packages.
# Current names are "hdbserver", "keyserver", "client"`.
# Cutoff date tested with "YYYY-MM-DD" format.
#
# It's better to run clean-ghcr-dry-run first
clean-ghcr image cutoff-date:
    source bin/clean-ghcr.sh &&
    delete-package-versions {{image}} {{cutoff-date}}

# Dry-run of clean-ghcr, will output the versions being deleted.
clean-ghcr-dry-run image cutoff-date:
    source bin/clean-ghcr.sh &&
    delete-package-versions-dry-run {{image}} {{cutoff-date}}
