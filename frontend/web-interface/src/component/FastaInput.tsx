/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { PrimaryButton } from "@securedna/frontend_common";
import { useRef, useState } from "react";
import { Setting } from "./Setting";

export interface FastaInputProps {
  disableReason?: string;
  getApi: (fasta: string) => void;
  onChange?: () => void;
}

export function FastaInput(props: FastaInputProps) {
  const [fasta, setFasta] = useState("");
  const [pickedFile, setPickedFile] = useState<File | undefined>(undefined);
  const fileInput = useRef<HTMLInputElement>(null);

  return (
    <Setting
      label="FASTA Content"
      input={(inputProps) => (
        <div className="space-y-2">
          <textarea
            {...inputProps}
            value={fasta}
            disabled={pickedFile !== undefined}
            onChange={(e) => {
              setFasta(e.target.value);
              props.onChange?.();
            }}
            placeholder="> Paste FASTA here or upload a file below"
            style={{ fontFamily: "monospace" }}
          />
          <div className="flex flex-row mb-8">
            <input
              className="flex-1 file:bg-secondary file:text-white file:rounded-lg file:px-4 file:py-2 file:me-3 enabled:file:cursor-pointer disabled:file:opacity-50"
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
            <PrimaryButton
              type="button"
              onClick={() => {
                setFasta("");
                setPickedFile(undefined);
                if (fileInput.current) fileInput.current.value = "";
              }}
              disabled={fasta === "" && pickedFile === undefined}
            >
              Clear
            </PrimaryButton>
          </div>
        </div>
      )}
    >
      <PrimaryButton
        type="button"
        className="py-3 text-lg"
        disabled={!fasta || !!props.disableReason}
        onClick={() => {
          props.getApi(fasta);
        }}
        title={!fasta ? "No FASTA entered" : props.disableReason}
      >
        Submit
      </PrimaryButton>
    </Setting>
  );
}
