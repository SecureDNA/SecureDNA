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
test-web-interface:
    cd web-interface && npm ci && npm exec tsc && npm test -- --passWithNoTests

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

build-arm version:
    #! /usr/bin/env bash
    # Set up vm (using gcloud here, but could be anywhere):
    # (If we want to increase core count beyond 4, we need to increase quota for us-central1 region, my last try was
    # rejected even though global quota increase was allowed)
    gcloud compute instances create arm-builder --zone=us-central1-a --image-project=debian-cloud --image-family=debian-12-arm64 --machine-type=t2a-standard-4

    # Setup build deps, build binaries. The `-A` flag forwards authentication agent for the `git clone`
    gcloud compute ssh --ssh-flag="-A" --zone=us-central1-a arm-builder -- 'bash -s {{version}}' < bin/setup-build-synthclient-tools.sh

    # package deb
    gcloud compute ssh --zone=us-central1-a arm-builder -- 'bash -s {{version}} securedna-dev/target/release arm64' < bin/package-deb.sh

    # Copy .deb off the vm:
    gcloud compute scp --zone=us-central1-a arm-builder:~/synthclient_{{version}}_arm64.deb .

    # Don't forget to delete the vm instance!
    gcloud compute instances delete --quiet --zone=us-central1-a arm-builder

# Copy to public repo
# excludes crates/doprf/bench, which includes a binary blog for queryset.
# requires, realpath, which is linux only (`brew install coreutils` on osx)
public version dirpath:
    #! /usr/bin/env bash
    set -euo pipefail

    dir=$(realpath {{dirpath}})
    echo "copying to public repo at $dir"
    temp=$(mktemp -d)
    wd="$temp/securedna-dev"
    git clone git@github.com:securedna/securedna-dev "$wd"
    cd "$wd"
    git checkout {{version}}
    rsync -av --progress --exclude .git --exclude .github --exclude ./crates/doprf/bench --exclude CHANGELOG.md . "$dir"
    cd ..
    rm -rf "$temp"

# Requires SECUREDNA_AHA_SECRET_KEY to be set
aha hdb hazard_path:
    cargo run --release -p awesome_hazard_analyzer -- --hdb-dir {{hdb}} --hazard-path {{hazard_path}} --debug --summary
