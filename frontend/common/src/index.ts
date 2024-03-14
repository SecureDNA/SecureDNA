/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

export * from "./components/CopyableCode";
export * from "./components/visualization/ScreeningVisualization";
export * from "./copyToClipboard";
export * from "./download";
export * as ncbi from "./ncbi";
export * from "./all_bindings";

export type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };
