# system_tests

Tests for synthclient + HDB + keyservers.

To run them, try these steps in the repo root:

```sh
earthly +dev
mkdir ./data
ln -s ../test/data/hdb ./data/hdb
./bin/start_test_environment.sh  # Runs "docker compose up -d".
cargo test --workspace --features run_system_tests
```

These tests are also run in CI, as `Docker Earthly - PR build and test`, [here](../.github/workflows/rust_build.yml).
