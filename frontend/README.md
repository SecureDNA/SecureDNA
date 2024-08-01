# frontend

Sub-monorepo for TypeScript/React frontends to SecureDNA code.

First run `cargo build --features wasm` in the monorepo root.

To build all frontends, run `pnpm install`, then `pnpm build`.

If a wasm module is not updating after changes, try deleting `node_modules`. Alternatively you can just delete the `node_modules/[certificates|quickdna]_wasm` directory, and `node_modules/.vite/deps/[certificates|quickdna]_wasm.js`.

See also: [web-interface/README.md](./web-interface/README.md) and [elgui/README.md](./elgui/README.md).
