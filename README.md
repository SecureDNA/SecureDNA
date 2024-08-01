<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# SecureDNA

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-informational?style=flat-square)](COPYRIGHT.md)

This is the monorepo for the [SecureDNA](https://securedna.org) project.

## Requirements

- You can find information about the project as a whole, including papers and a live demo, at the [main site](https://securedna.org).
- This should work in an up-to-date `linux-amd64` environment (tested on ubuntu 22.04, debian Bookworm) and recent Rust toolchain. Check the [toolchain file](./rust-toolchain.toml) for the current version. It has also been successfully built for `linux-arm64`.
- Current precompiled `synthclient` binaries are available for [Ubuntu amd64](https://github.com/SecureDNA/ppa).
- To use the production servers with real databases, you'll need to [obtain certificates](https://securedna.org/start/), but you can compile the entire system below and run test servers with test databases and your own certificates.

## Structure

- `crates/` contains all the crates in the monorepo workspace.
   - `awesome_hazard_analyzer/`: A Rust crate combining `hdb` and `synthclient` into one fast local hazard analyzer which bypasses crypto and networking
   - `base64_helper`: Base64 serialization helpers for 32-byte arrays
   - `certificate_client/`: a command line interface for managing SecureDNA certificates.
   - `certificates/`: a library for managing SecureDNA certificates, used to request exemptions from DNA synthesis restrictions.
   - `certificate_tests/`: tests that our test and production certificates and tokens function as expected.
   - `doprf/`: a Rust implementation of DOPRF ("distributed oblivious pseudo-random function"), the distributed hashing technique we use.
   - `doprf_client/`: a Rust server that actually talks to keyservers using DOPRF and sends the result to the HDB.
   - `hdb/`: the HDB (hash database) implementation.
   - `hdbserver/`: HDB server holding hazard information.
   - `keyserver/`: one of the keyservers used in DOPRF.
   - `minhttp`: minimal tools for building HTTP servers with `hyper`
   - `packed_ristretto/`: internal API data format used in DOPRF by synthclient, the keyservers, and the HDB.
   - `performance_tests/`: performance tests built around Goose
   - `pipeline_bridge/`: types for interfacing with the output of the pipeline.
   - `securedna_versioning/`: a Rust crate that simply exposes a function for getting a monorepo version string.
   - `shared_types/`: Rust type definitions shared by several monorepo components.
   - `streamed_ristretto/`: internal API data format used in DOPRF by `synthclient`, the keyservers and the HDB.
   - `synthclient/`: a Rust server that runs within the client's premises. It generates windows from a FASTA string, then communicates with other components (see `doprf_client/`) to hash the windows and check them for hazards.
   - `system_tests/`: tests for `synthclient/`.
   - `wasm_bindings/`: WebAssembly bindings, for running screening and certificates code in the browser. Used by `elgui`.
- `bin/`: assorted shell scripts.
- `docs/`: assorted general documentation.
- `frontend/`: React and TypeScript code for the various web interfaces to SecureDNA.
   - `common/`: React components and type definitions shared by `web-interface` and `elgui`.
   - `web-interface/`: for easily submitting queries to your local `synthclient`.
   - `elgui/`: for requesting and approving exemptions.
   - `tsgen/`: translates Rust type definitions into TypeScript.
- `test/`: test data used for local development. You can `ln -s test/data data` to run the system with a small "test HDB".
- `Earthfile`: Similar to a Makefile, script for building containers for `synthclient`, `hdbserver`, and each `keyserver`. Requires [Earthly](https://earthly.dev).
- `.earthlyignore`: Equivalent to `.dockerignore` for Earthly.
- `docker-compose.yml`: Docker Compose development config.

## How to run

### Using Earthly and Docker

Local setup:

`docker-compose.yml` has `hdbserver` look for the hdb at `data/hdb`.

If you want to use the test hdb for local dev, run `ln -s test/data data` in the repo root (for *nix users).

1. Install [Earthly](https://earthly.dev)
   - Earthly is a tool similar to `make`, but builds
     the targets inside containers.
2. Run `earthly +dev && docker compose up`
   1. `earthly +dev` will rebuild the containers.
   2. `docker compose up` will launch the containers and expose `client`
      on `http://localhost`
      - If `docker compose` doesn't work, you may need to try `docker-compose`
        (note the dash) instead: `earthly +dev && docker-compose up`

### Without containerization

A script to build and run w/out containerization: [local_test_environment.sh](./bin/local_test_environment.sh).

To build the repository, install rust and run `cargo build`.

To build the frontend, install [pnpm 8](https://pnpm.io/) and [wasm-pack 0.12.1+](https://rustwasm.github.io/wasm-pack/), then run `cargo build --features wasm`. Then follow the instructions in [the frontend README](./frontend/README.md).

## Example usage

Once you have synthclient running, either via Earthly or `cargo run`, try the following command (needs [jq](https://stedolan.github.io/jq/)):

```bash
echo -e ">Influenza_segment_1\nggcacatctggggtggagtctgctgtcctgagaggatttctcattttcgacaaagaagacaagagatatgacctagcattaagcatcaatgaactgagcaatcttgcaaaaggagagaaggctaatgtgctaattgggcaaggggacgtagtgttggtaatgaaacgaaaacgggactctagcatacttactgacagccagacagcgaccaaaagaattcggatggccatcaattag\n" | jq -sR '{fasta: ., region: "all"}' | curl localhost/v1/screen -d@-
```

You should get a response after a couple seconds. The response format is documented in the [API](https://pages.securedna.org/production/assets/Synthclient-API.pdf).

## Development

### Just

For a quick reference to important tasks visible at the repo root, see the `justfile`. Tasks in the `justfile` are run by the `just` executable. For details (including installation), see https://github.com/casey/just.

As an example, to run the system tests:
- `just run-docker-with-test-hdb` will build docker images for backend, link to the test hdb in this repo, and run the system in the background.
- You can follow up with `just test-system`, which will run tests against the system started in the previous step.

### Nix

For developers who use nix, there is a `flake.nix` which sets up a local dev environment that includes all dev dependencies and language toolchains, as well as miscellaneous tools. Note that `docker` is not included, it must be installed separately.

## Packaging

We currently package synthclient and cert tools for debian-based distros (ubuntu 22.04, debian Bookworm and later).

### amd64

We run this on github actions, and make it available on our own PPA.

### arm64

We run this manually, and make it available on our own PPA. In the future, we may also run it on github actions (once runners are available). For now, use `just build-arm <version>`
