/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import * as path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import topLevelAwait from "vite-plugin-top-level-await";
import wasm from "vite-plugin-wasm";

// https://vitejs.dev/config/
export default defineConfig(({ command, mode }) => ({
  plugins: [react(), wasm(), topLevelAwait()],
  resolve: {
    alias: {
      "@securedna/frontend_common": path.resolve(
        __dirname,
        "../common/src/index.ts",
      ),
    },
  },

  build: {
    lib: {
      entry: "src/component/ScreeningVisualization.tsx",
      name: "ScreeningVisualization",
      formats: ["es", "umd"],
      fileName: (format) => `visualization.${format}.js`,
    },
    rollupOptions: {
      external: ["react", "react-dom", "styled-components"],
      output: {
        globals: {
          react: "React",
          "react-dom": "ReactDOM",
          // "styled-components": "styled",
        },
      },
    },
  },
}));
