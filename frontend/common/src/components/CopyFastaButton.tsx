/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { type Sequence, copyToClipboard } from "..";
import { unparseSequence } from "../util/sequence";

/**
 * A button that copies the given FASTA sequence to the user's clipboard.
 */
export function CopyFastaButton(props: { sequence: string | Sequence }) {
  const sequence = props.sequence;
  return (
    <button
      type="button"
      className="bg-gray-200 px-2 py-1 rounded-sm hover:bg-gray-300 text-sm cursor-pointer"
      onClick={async () =>
        copyToClipboard(
          "FASTA",
          typeof sequence === "string" ? sequence : unparseSequence(sequence),
        )
      }
    >
      Copy FASTA
    </button>
  );
}
