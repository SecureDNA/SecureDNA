/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faUpload } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useRef, useState } from "react";
import { Button } from "./Button";

export interface DragUploadProps {
  accept: string;
  onFile: (file: ArrayBuffer | undefined) => void;
  small?: boolean;
  label?: string;
}

export const DragUpload = (props: DragUploadProps) => {
  const [dragging, setDragging] = useState(false);
  const uploadRef = useRef<HTMLInputElement>(null);

  const onFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (loaded) => {
      const result = loaded.target?.result;
      if (result && result instanceof ArrayBuffer) {
        props.onFile(result);
      } else {
        props.onFile(undefined);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const onUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files?.[0]) {
      onFile(event.target.files[0]);
    } else {
      props.onFile(undefined);
    }
  };

  const onDrag = (e: React.DragEvent<HTMLButtonElement>) => {
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

  return (
    <>
      {props.small ? (
        <Button
          type="button"
          onClick={() => uploadRef?.current?.click()}
          onDragEnter={onDrag}
          onDragOver={onDrag}
          onDragLeave={onDrag}
          onDragEnd={onDrag}
          onDrop={onDrag}
        >
          {props.label ?? `Select ${props.accept}`}
        </Button>
      ) : (
        <button
          type="button"
          onClick={() => uploadRef?.current?.click()}
          onDragEnter={onDrag}
          onDragOver={onDrag}
          onDragLeave={onDrag}
          onDragEnd={onDrag}
          onDrop={onDrag}
          className={`w-36 h-36 p-4 text-center rounded-2xl flex flex-col items-center justify-center transition hover:bg-secondary hover:text-white ${dragging ? "bg-secondary text-white" : "bg-primary"}`}
        >
          <FontAwesomeIcon
            icon={faUpload}
            size="3x"
            className="mb-2 pointer-events-none"
          />
          {props.label ?? `Select ${props.accept}`}
        </button>
      )}
      <input
        hidden
        type="file"
        accept={props.accept}
        onChange={onUpload}
        ref={uploadRef}
      />
    </>
  );
};
