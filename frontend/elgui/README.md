# ELGUI web frontend

ELGUI is a web app that lets researchers request exemptions for known hazardous organisms and lets biosafety officers approve those requests. This produces a cryptographic "exemption token" that can be supplied alongside a synthesis order.

ELGUI is a static site. The cert-signing and screening happen in the browser, powered by WebAssembly. See `crates/wasm_bindings`.

## Usage

Use `pnpm install && pnpm dev` to spin up a dev server at <http://localhost:5173>.

To host it from somewhere (e.g. BF), run `pnpm dev --port 29898 --host`. You can configure the port number. The [`--host` flag](https://vitejs.dev/config/server-options.html#server-host) means the same as `--host 0.0.0.0` and tells the Vite dev server to listen on all addresses rather than just `localhost`.

To run tests, compile the WebAssembly bindings with `cd ../..; cargo build --features wasm` then run `pnpm test`.
