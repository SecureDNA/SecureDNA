/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faCancel, faCheck } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useRef, useState } from "react";
import type { Result } from "../..";
import { PrimaryButton } from "../PrimaryButton";

export type AuthFileResult = Result<
  { array: Uint8Array; name: string },
  string
>;

/**
 * An onChange handler for file uploads that calls a bound setter with the
 * contents of the uploaded file.
 */
function loadFromFile(
  header: string,
  setter: (result: AuthFileResult) => void,
  e: React.ChangeEvent<HTMLInputElement> | File,
): void {
  let file: File;
  if ("currentTarget" in e) {
    const files = e.currentTarget.files;
    if (!files || files.length === 0) {
      setter({ ok: false, error: "No file was selected." });
      return;
    }
    if (files.length > 1) {
      setter({ ok: false, error: "Multiple file upload is not allowed." });
      return;
    }
    file = files[0];
  } else {
    file = e;
  }
  const name = file.name;
  const reader = new FileReader();
  reader.onerror = () => {
    setter({ ok: false, error: `File ${file.name} could not be read.` });
  };
  reader.onload = (loaded) => {
    const array = new Uint8Array(loaded.target?.result as ArrayBuffer);
    const headerView = array.slice(0, header.length);
    const headerText = new TextDecoder().decode(headerView) ?? "";
    if (!headerText.startsWith(header)) {
      setter({
        ok: false,
        error: `File ${file.name} is not a valid certificate.`,
      });
      return;
    }
    setter({ ok: true, value: { array, name } });
  };
  reader.readAsArrayBuffer(file);
}

interface FileUploadProps {
  header: string;
  pem: AuthFileResult | undefined;
  setPem: (pem: AuthFileResult) => void;
  label: string;
  noun: string;
  acceptExtension: string;
}

export const FileUpload = ({
  header,
  pem,
  setPem,
  label,
  acceptExtension,
}: FileUploadProps) => {
  const inputRef = useRef<HTMLInputElement>(null);

  const [dragging, setDragging] = useState(false);

  const onFile = (file: File) => {
    loadFromFile(header, setPem, file);
  };

  const onDrag = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    switch (e.type) {
      case "dragenter":
      case "dragover":
        setDragging(true);
        break;
      case "drop":
        if (e.dataTransfer.files.length === 1) {
          onFile(e.dataTransfer.files[0]);
        }
        setDragging(false);
        break;
      case "dragleave":
      case "dragend":
        setDragging(false);
        break;
    }
  };

  let zoneClasses =
    "flex-1 text-center border-dashed border border-black/20 border-2 p-4";
  if (dragging) zoneClasses += " bg-blue-300/10";
  return (
    <div
      className={zoneClasses}
      onDragEnter={onDrag}
      onDragOver={onDrag}
      onDragLeave={onDrag}
      onDragEnd={onDrag}
      onDrop={onDrag}
    >
      Drag and drop or <br />
      <PrimaryButton
        type="button"
        className="my-2"
        onClick={() => inputRef.current?.click()}
      >
        {label}
      </PrimaryButton>
      <br />
      <input
        ref={inputRef}
        hidden
        type="file"
        accept={acceptExtension}
        onChange={loadFromFile.bind(this, header, setPem)}
      />
      <div className="select-none w-full">
        {pem?.ok === false ? (
          <p className="text-error overflow-hidden text-ellipsis text-sm">
            <FontAwesomeIcon icon={faCancel} className="mr-2" />
            {pem.error}
          </p>
        ) : pem?.ok === true ? (
          <p className="text-success overflow-hidden text-ellipsis text-sm">
            <FontAwesomeIcon icon={faCheck} className="mr-2" />
            Selected {pem.value.name}
          </p>
        ) : (
          <p className="opacity-50 overflow-hidden text-ellipsis text-sm">
            No file selected
          </p>
        )}
      </div>
    </div>
  );
};
