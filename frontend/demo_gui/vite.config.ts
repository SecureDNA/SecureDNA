/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import legacy from "@vitejs/plugin-legacy";
import * as path from "path";

// https://vitejs.dev/config/
export default defineConfig(({ command, mode }) => ({
  server: {
    fs: {
      strict: false,
    },
  },
  plugins: [
    react(),
    wasm(),
    topLevelAwait(),
    legacy({
      targets: ["defaults", "not IE 11"],
    }),
  ],
  resolve: {
    alias: {
      "@securedna/frontend_common": path.resolve(
        __dirname,
        "../common/src/index.ts"
      ),
    },
  },
}));
