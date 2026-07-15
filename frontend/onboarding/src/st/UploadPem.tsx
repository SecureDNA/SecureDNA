/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { useCallback, useRef, useState } from "react";

export function UploadPem(props: {
  title: string;
  header: string;
  accept: string;
  disabled?: boolean;
  hideHeading?: boolean;
  onUpload: (pem: string) => void;
}) {
  const inputRef = useRef(null);
  const [uploadError, setUploadError] = useState("");
  const { accept, header, title, disabled, hideHeading, onUpload } = props;

  const onUploadFile = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      if (event.target.files?.[0]) {
        const reader = new FileReader();
        reader.onload = (loaded) => {
          const result = loaded.target?.result;
          if (result && result instanceof ArrayBuffer) {
            const pem = new Uint8Array(result);
            const pemString = new TextDecoder().decode(pem).trim();
            if (!pemString.startsWith(header)) {
              setUploadError(
                `Invalid PEM file. Upload a file starting with: ${header}`,
              );
              onUpload("");
              event.target.value = "";
              return;
            }
            try {
              onUpload(pemString);
              setUploadError("");
            } catch (e) {
              setUploadError(`Could not parse PEM file: ${e}`);
              onUpload("");
              event.target.value = "";
            }
          } else {
            setUploadError("Could not parse PEM file.");
            onUpload("");
            event.target.value = "";
          }
        };
        reader.readAsArrayBuffer(event.target.files[0]);
      }
    },
    [onUpload, header],
  );

  return (
    <div className="flex-1">
      {!hideHeading && (
        <h3>
          {title} ({accept})
        </h3>
      )}
      <p>
        <input
          disabled={disabled}
          className="file:bg-secondary file:text-white file:rounded-full file:px-4 file:py-2 enabled:file:cursor-pointer disabled:file:opacity-50"
          ref={inputRef}
          type="file"
          accept={accept}
          onChange={onUploadFile}
        />
      </p>
      {uploadError && <p className="text-error">{uploadError}</p>}
    </div>
  );
}
