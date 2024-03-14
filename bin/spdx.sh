#!/usr/bin/env bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if ! command -v 'addlicense' &> /dev/null; then
  echo "Error: 'addlicense' is not installed."
  exit 1
fi

action="check"
if [ $# -gt 0 ]; then
  case "$1" in
    --check)
      action="check"
      ;;
    --add)
      action="add"
      ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage:"
      echo "  $0 --check: Check for missing license headers."
      echo "  $0 --add:   Add license headers to files without them."
      echo "  With no arguments, runs --check."
      exit 1
      ;;
    esac
fi

# not all of these files are present in CI, but this way you can use this
# script locally as well
ignores=(
  -ignore '**/*.yaml'
  -ignore '**/*.yml'
  -ignore '**/node_modules/**'
  -ignore '**/target_wasm/**'
  -ignore 'crates/wasm_bindings/**/pkg/**'
  -ignore 'crates/wasm_bindings/**/pkg_node/**'
  -ignore 'frontend/common/src/all_bindings.ts'
  -ignore 'target/**'
  -ignore 'test/certs/**'
  -ignore 'test/data/**'
)

if [[ "$action" = "check" ]]; then
  addlicense "${ignores[@]}" -check .
else
  org="SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>"
  addlicense               \
    "${ignores[@]}"        \
    -y "2021-$(date +%Y)"  \
    -c "$org"              \
    -l "MIT OR Apache-2.0" \
    -s=only                \
    .
fi
