/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/// Make a descriptive file name for an exemption list, based on who requested
/// it, like: `John-Doe-2023-01-19`
export function makeFileName(requestorName: string | null | undefined) {
  const hyphenated = (requestorName || "Anonymous")
    .replaceAll(/\W+/gu, "-")
    .replaceAll(/-+/gu, "-")
    .replaceAll(/^-|-$/gu, "");
  const yyyymmdd = new Date().toISOString().split("T")[0];
  return hyphenated + "-" + yyyymmdd;
}

/// Download a string, Uint8Array or Blob as a file in the user's browser.
export function download(
  content: string | Uint8Array | Blob,
  mimeType: string,
  filename: string
) {
  const blob =
    content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.setAttribute("href", url);
  a.setAttribute("download", filename);
  a.click();
}
