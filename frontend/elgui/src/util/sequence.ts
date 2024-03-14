/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { Sequence } from "@securedna/frontend_common";

export function unparse(sequence: Sequence): string {
  return sequence.records
    .map((record) => ">" + record.header + "\n" + record.contents)
    .join("\n");
}
