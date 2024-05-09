/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/// <reference types="vitest" />
/// <reference types="vite/client" />

import { AliasOptions, ConfigEnv, defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import legacy from "@vitejs/plugin-legacy";
import { viteStaticCopy } from "vite-plugin-static-copy";
import crossOriginIsolation from "vite-plugin-cross-origin-isolation";
import { resolve } from "path";
import { execSync } from "child_process";

const forwardToTrailingSlash = {
  name: "forward-to-trailing-slash",
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (/^\/elgui\/[a-z-]+$/.test(req.url)) {
        res.writeHead(301, { Location: `${req.url}/` });
      }
      next();
    });
  },
};

const wasmContentTypePlugin = {
  name: "wasm-content-type-plugin",
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (req.url.endsWith(".wasm")) {
        res.setHeader("Content-Type", "application/wasm");
      }
      next();
    });
  },
};

// https://vitejs.dev/config/
export default () => {
  const date = execSync("git log -1 --format=%cI");
  const branch = execSync("git rev-parse --abbrev-ref HEAD");
  const hash = execSync("git rev-parse HEAD");

  let alias: AliasOptions = {
    src: resolve("./src"),
    "@securedna/frontend_common": resolve(__dirname, "../common/src/index.ts"),
  };

  console.log(resolve(__dirname, "../common/src/index.ts"));

  if (process.env.VITEST) {
    alias.certificates_wasm = resolve(
      __dirname,
      "../../crates/wasm_bindings/certificates/pkg/certificates_wasm.js"
    );
    alias.quickdna_wasm = resolve(
      __dirname,
      "../../crates/wasm_bindings/quickdna/pkg/quickdna_wasm.js"
    );
  }

  process.env.VITE_GIT_COMMIT_DATE = date.toString().trimEnd();
  process.env.VITE_GIT_BRANCH_NAME = branch.toString().trimEnd();
  process.env.VITE_GIT_COMMIT_HASH = hash.toString().trimEnd();
  return defineConfig({
    appType: "mpa",
    plugins: [
      viteStaticCopy({
        targets: [
          {
            src: "./node_modules/screening_wasm/*",
            dest: "./screening_wasm",
          },
        ],
      }),
      react(),
      wasm(),
      topLevelAwait(),
      legacy({
        targets: ["defaults", "not IE 11"],
      }),
      wasmContentTypePlugin,
      crossOriginIsolation(),
      forwardToTrailingSlash,
    ],
    test: {
      globals: true,
      environment: "jsdom",
      root: ".",
    },
    server: {
      fs: {
        strict: false,
      },
      headers: {
        "cross-origin-embedder-policy": "credentialless",
      },
    },
    resolve: { alias },
    root: "./views",
    base: "/elgui/",
    build: {
      outDir: resolve(__dirname, "dist"),
      rollupOptions: {
        input: {
          approve: resolve(__dirname, "views/approve/index.html"),
          "inspect-elt": resolve(__dirname, "views/inspect-elt/index.html"),
          request: resolve(__dirname, "views/request/index.html"),
        },
      },
    },
    optimizeDeps: {
      exclude: ["screening_wasm"],
    },
  });
};
