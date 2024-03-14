# tsgen

This tool looks for types tagged `// tsgen` in our Rust codebase, and translates them to TypeScript types that are compatible with `serde_json`.

It consists of:

- a JavaScript module `tsgen.js` which can translate Rust code into TypeScript types;
- a Node.js script `main.js` which runs tsgen on all our Rust code and writes the result to the right places.

It runs as part of a WebAssembly-enabled monorepo build (`cargo build --features wasm`): it's invoked by `crates/wasm_bindings/build.rs` after it runs `wasm-pack`.

You can also run it manually by running `pnpm run tsgen` from this directory.

The output is written to all of the following paths:

- `crates/wasm_bindings/certificates/pkg/all_bindings.ts`
- `crates/wasm_bindings/screening/pkg/all_bindings.ts`
- `frontend/common/src/all_bindings.ts`
