/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/// <reference types="vitest" />
/// <reference types="vite/client" />

import { AliasOptions, PluginOption, defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import legacy from "@vitejs/plugin-legacy";
import { resolve } from "path";
import { execSync } from "child_process";

const forwardToTrailingSlash: PluginOption = {
  name: "forward-to-trailing-slash",
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (/^\/elgui\/[a-z-]+$/.test(req.url ?? "")) {
        res.writeHead(301, { Location: `${req.url}/` });
      }
      next();
    });
  },
};

const wasmContentTypePlugin: PluginOption = {
  name: "wasm-content-type-plugin",
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (req.url?.endsWith(".wasm")) {
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

  const alias: AliasOptions = {
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
      react(),
      wasm(),
      topLevelAwait(),
      legacy({
        targets: ["defaults", "not IE 11"],
      }),
      wasmContentTypePlugin,
      forwardToTrailingSlash,
    ],
    test: {
      globals: true,
      environment: "jsdom",
      root: ".",
    },
    resolve: { alias },
    base: "/onboarding/",
    build: {
      outDir: resolve(__dirname, "dist"),
    },
    optimizeDeps: {
      // exclude: ["screening_wasm"],
    },
  });
};
