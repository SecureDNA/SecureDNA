/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { FastaFile } from "src/types";

export interface ScreeningWorkerParams {
  sequence: string | FastaFile;
  synthTokenContents: number[] | Uint8Array;
  privContents: number[] | Uint8Array;
  privPassphrase: string;
}

export interface ScreeningWorkerMessage extends ScreeningWorkerParams {
  command: "screen";
  requestId: string;
}
