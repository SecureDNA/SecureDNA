/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { useRef, useState } from "react";
import { Setting } from "./Setting";
import { SubmitButton } from "./SubmitButton";

export interface FastaInputProps {
  disableReason?: string;
  getApi: (fasta: string) => void;
}

export function FastaInput(props: FastaInputProps) {
  const [fasta, setFasta] = useState("");
  const [pickedFile, setPickedFile] = useState<File | undefined>(undefined);
  const fileInput = useRef<HTMLInputElement>(null);

  return (
    <Setting
      label="FASTA Content"
      input={(props) => (
        <div className="space-y-2">
          <textarea
            {...props}
            value={
              pickedFile ? `(uploaded file, ${fasta.length} bytes)` : fasta
            }
            disabled={pickedFile !== undefined}
            onChange={(e) => setFasta(e.target.value)}
            placeholder="> Paste FASTA here or upload a file below"
            style={{ fontFamily: "monospace" }}
          />
          <input
            type="file"
            ref={fileInput}
            onChange={(e) => {
              const files = e.currentTarget.files;
              if (files && files.length > 0) {
                const reader = new FileReader();
                const file = files[0];
                reader.onload = (loaded) => {
                  const result = loaded.target?.result;
                  if (typeof result === "string") {
                    setFasta(result);
                    setPickedFile(file);
                  }
                };
                reader.readAsText(file);
              } else {
                setFasta("");
                setPickedFile(undefined);
              }
            }}
          />
          <button
            className="float-right border enabled:border-primary/50 disabled:bg-black/10 enabled:text-primary enabled:hover:bg-primary/20 enabled:cursor-pointer rounded px-2 flex-none disabled:opacity-50"
            onClick={() => {
              setFasta("");
              setPickedFile(undefined);
              if (fileInput.current) fileInput.current.value = "";
            }}
            disabled={fasta === "" && pickedFile === undefined}
          >
            Clear
          </button>
        </div>
      )}
    >
      <SubmitButton
        disabled={!fasta || !!props.disableReason}
        onClick={() => {
          props.getApi(fasta);
        }}
        title={!fasta ? "No FASTA entered" : props.disableReason}
      />
    </Setting>
  );
}
