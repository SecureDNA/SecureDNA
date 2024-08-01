/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import toast from "react-hot-toast";

export async function copyToClipboard(
  description: string,
  contents: string,
): Promise<void> {
  if (navigator.clipboard) {
    await navigator.clipboard.writeText(contents);
    toast.success(`Copied ${description} to clipboard.`);
  } else {
    const textArea = document.createElement("textarea");
    textArea.value = contents;
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      document.execCommand("copy");
      toast.success(`Copied ${description} to clipboard.`);
    } catch (err) {
      toast.error(
        `Unable to copy ${description} to clipboard. Check the developer console.`,
      );
      console.error("copyToClipboard failed:", { description, err, contents });
    }
    document.body.removeChild(textArea);
  }
}
