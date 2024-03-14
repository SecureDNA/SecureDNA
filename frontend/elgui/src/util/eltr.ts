/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { ExemptionListTokenRequest } from "@securedna/frontend_common";

export function needsScreening(eltr: ExemptionListTokenRequest): boolean {
  return eltr.V1.exemptions.some((organism) =>
    organism.sequences.some(
      (sequence) => "Dna" in sequence && sequence.Dna.records.length > 0
    )
  );
}
