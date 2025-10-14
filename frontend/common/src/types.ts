/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type {
  BundleCheckError,
  CertBundlePreIssuanceError,
} from "./all_bindings";

export type CertCheckResult =
  | { Ok: undefined }
  | { Err: CertBundlePreIssuanceError };

export type BundleCheckResult = { Ok: undefined } | { Err: BundleCheckError };

export type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };
