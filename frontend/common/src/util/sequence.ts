/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { Sequence } from "..";

export function unparseSequence(sequence: Sequence): string {
  return sequence.records
    .map((record) => `>${record.header}\n${record.contents}`)
    .join("\n");
}
