/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import React from "react";
import { copyToClipboard } from "../copyToClipboard";

export const CopyableCode = (props: { description: string; text: string }) => (
  <div className="relative bg-white border rounded">
    <div className="max-h-48 overflow-scroll">
      <pre className="font-mono text-sm py-2 px-4">{props.text}</pre>
    </div>
    <button
      type="button"
      className="absolute top-2 right-6 bg-gray-200 px-2 py-1 rounded hover:bg-gray-300 text-sm"
      onClick={() => copyToClipboard(props.description, props.text)}
    >
      Copy to clipboard
    </button>
  </div>
);
