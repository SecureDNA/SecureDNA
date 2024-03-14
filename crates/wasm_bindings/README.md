# wasm_bindings

WebAssembly bindings used by other code in the SecureDNA monorepo (such as `frontend/elgui`).

To check the WebAssembly build, try `cargo check-wasm` (an alias defined in .cargo/config.toml).

To build the WebAssembly files to `*/pkg`, install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) and run `cargo build --features wasm`.

To run wasm-pack with custom flags, try e.g. `WASM_PACK_FLAGS="--dev" cargo build --features wasm`.
