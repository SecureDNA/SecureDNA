/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { ApiResponse } from "@securedna/frontend_common";
import { FastaFile } from "src/types";
import screeningWorkerUrl from "./worker?url";

export type ScreeningProgress =
  | { done: false; progress: number }
  | { done: true; result: ApiResponse };

let num = 0;

/// Run screening in a Web Worker.
export async function performScreening(
  args: {
    sequence: string | FastaFile;
    apiKey: string;
  },
  callback: (progress: ScreeningProgress) => void
): Promise<void> {
  const { sequence, apiKey } = args;
  const url = new URL(screeningWorkerUrl, import.meta.url);
  const screenWorker = new Worker(url, { type: "module" });

  // Wait for the "ready" message.
  await new Promise<void>((res) => {
    screenWorker.onmessage = () => res();
  });

  const requestId = `screen${++num}`;
  const channel = new MessageChannel();
  channel.port2.onmessage = (e) => callback(e.data);

  const message = { command: "screen", requestId, apiKey, sequence };
  screenWorker.postMessage(message, [channel.port1]);
}
