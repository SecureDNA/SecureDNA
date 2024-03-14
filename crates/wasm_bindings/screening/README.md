# wasm_bindings

WebAssembly bindings for screening (`synthclient` and `doprf_client`).

The build is managed by `build.rs` of the parent project: try `cd .. && cargo build --features wasm`.

## Testing

First, set up a local test environment (local hash database and keyservers):

```sh
cd ../../..; bash bin/local_test_environment.sh  # uncontainerized
# OR
cd ../../..; earthly +dev; docker compose up -d  # using Docker
```

Then run [`wasm-pack`](https://github.com/rustwasm/wasm-pack) `test`:

```sh
wasm-pack test --headless --chrome
wasm-pack test --headless --firefox
```
