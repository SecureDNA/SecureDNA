/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { type SequenceIdentifier, ncbi } from "@securedna/frontend_common";
import { CopyFastaButton } from "./CopyFastaButton";

export function SequenceLink(props: { identifier: SequenceIdentifier }) {
  const { identifier } = props;
  if ("Dna" in identifier) {
    return <CopyFastaButton sequence={identifier.Dna} />;
  }
  const url = ncbi.url(identifier.Id);
  return <a href={url}>{identifier.Id}</a>;
}
