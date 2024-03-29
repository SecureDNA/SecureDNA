/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

const fs = require("fs");
const path = require("path");
const { tsgen } = require("./tsgen");

const outDirs = [
  "crates/wasm_bindings/certificates/pkg",
  "crates/wasm_bindings/screening/pkg",
  "frontend/common/src",
];

const ignoredDirs = ["target", "target_wasm", "node_modules"];

function* walkSync(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!ignoredDirs.includes(entry.name))
        yield* walkSync(path.join(dir, entry.name));
    } else {
      yield path.join(dir, entry.name);
    }
  }
}

// Find the repository root.
while (!fs.existsSync("./frontend")) process.chdir("..");

let output = ["// Generated by `tsgen` in the SecureDNA monorepo."];

for (const path of walkSync(".")) {
  if (path.endsWith(".rs")) {
    const source = fs.readFileSync(path, "utf-8");
    output.push(...tsgen(source, path));
  }
}

let bindings = output.join("\n") + "\n";

if (process.argv.includes("--show-bindings")) {
  console.log(bindings);
}

for (const dir of outDirs) {
  if (fs.existsSync(dir)) {
    fs.writeFileSync(path.join(dir, "all_bindings.ts"), bindings);
  } else {
    console.warn(`outDir ${dir} missing!`);
  }
}
