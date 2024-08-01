/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { type Sequence, copyToClipboard } from "@securedna/frontend_common";
import { unparse } from "src/util/sequence";

/**
 * A button that copies the given FASTA sequence to the user's clipboard.
 */
export function CopyFastaButton(props: { sequence: Sequence }) {
  return (
    <button
      type="button"
      className="bg-gray-200 px-2 py-1 rounded hover:bg-gray-300 text-sm"
      onClick={async () => copyToClipboard("FASTA", unparse(props.sequence))}
    >
      Copy FASTA
    </button>
  );
}
