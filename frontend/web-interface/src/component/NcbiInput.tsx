/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { PrimaryButton } from "@securedna/frontend_common";
import { useState } from "react";
import { Setting } from "./Setting";

export interface NcbiInputProps {
  disableReason?: string;
  getNcbiApi: (accessionNumber: string) => void;
  onChange?: () => void;
}

export function NcbiInput(props: NcbiInputProps) {
  const [an, setAn] = useState("");

  return (
    <Setting
      label="NCBI Accession Number"
      input={(inputProps) => (
        <input
          {...inputProps}
          type="text"
          value={an}
          onChange={(e) => {
            setAn(e.target.value);
            props.onChange?.();
          }}
          placeholder="XY123..."
        />
      )}
    >
      <PrimaryButton
        type="button"
        disabled={!an || !!props.disableReason}
        onClick={() => props.getNcbiApi(an)}
        title={!an ? "No accession number entered" : props.disableReason}
      >
        Submit
      </PrimaryButton>
    </Setting>
  );
}
