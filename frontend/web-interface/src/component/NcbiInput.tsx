/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { useState } from "react";
import { Setting } from "./Setting";
import { SubmitButton } from "./SubmitButton";

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
      <SubmitButton
        disabled={!an || !!props.disableReason}
        onClick={() => props.getNcbiApi(an)}
        title={!an ? "No accession number entered" : props.disableReason}
      />
    </Setting>
  );
}
