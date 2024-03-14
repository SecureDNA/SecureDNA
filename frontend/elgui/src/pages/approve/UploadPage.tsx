/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faUpload } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { ExemptionListTokenRequest, Result } from "@securedna/frontend_common";
import React, { useCallback, useRef } from "react";
import { eltrPemToJsObject } from "src/util/sign_eltr";
import { useApprovalStore } from "./store";

const UploadPage = () => {
  const [dragging, setDragging] = React.useState(false);
  const setEltr = useApprovalStore((state) => state.setEltr);
  const setEltrPem = useApprovalStore((state) => state.setEltrPem);
  const advance = useApprovalStore((state) => state.advance);

  const upload = useCallback(
    (
      eltr: ExemptionListTokenRequest | undefined,
      eltrPem: Result<Uint8Array, string>
    ) => {
      setEltr(eltr);
      setEltrPem(eltrPem);
      if (eltr && eltrPem.ok) {
        advance();
      }
    },
    [advance]
  );

  const handleFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (loaded) => {
      const result = loaded.target?.result;
      if (result && result instanceof ArrayBuffer) {
        const pem = new Uint8Array(result);
        try {
          const json = eltrPemToJsObject(pem);
          upload(json, { ok: true, value: pem });
        } catch (e) {
          upload(undefined, {
            ok: false,
            error: "Could not parse ELTR file: " + e,
          });
        }
      } else {
        upload(undefined, {
          ok: false,
          error: "Could not parse ELTR file.",
        });
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const onUploadEltr = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      handleFile(event.target.files[0]);
    }
  };

  const uploadEltrRef = useRef<HTMLInputElement>(null);
  const eltrPem = useApprovalStore((state) => state.eltrPem);

  const handleDrag = (e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault();
    e.stopPropagation();
    switch (e.type) {
      case "dragenter":
      case "dragover":
        setDragging(true);
        break;
      case "drop":
        if (e.dataTransfer.files.length === 1) {
          handleFile(e.dataTransfer.files[0]);
        }
      case "dragleave":
      case "dragend":
        setDragging(false);
        break;
    }
  };

  return (
    <div>
      <p className="mb-4">
        This tool allows an authorized party to approve a researcher’s request
        for DNA screening exemptions.
      </p>
      <p className="mb-4">
        Select an <b>.eltr</b> file ("exemption list token request") to get
        started.
      </p>
      <p className="my-4 flex justify-center">
        <button
          type="button"
          onClick={() => uploadEltrRef?.current?.click()}
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDragEnd={handleDrag}
          onDrop={handleDrag}
          className={
            "w-36 h-36 p-4 text-center text-white rounded-2xl flex flex-col items-center justify-center shadow-lg transition hover:bg-primary-light" +
            (dragging ? " bg-primary-light" : " bg-primary")
          }
        >
          <FontAwesomeIcon
            icon={faUpload}
            size="3x"
            className="opacity-50 mb-2 pointer-events-none"
          />
          {"Select .eltr"}
        </button>
        <input
          hidden
          type="file"
          accept=".eltr"
          onChange={onUploadEltr}
          ref={uploadEltrRef}
        />
      </p>
      <p>
        Researchers can create .eltr files using the{" "}
        <a className="text-primary underline hover:opacity-50" href="./request">
          Exemption List Request Tool.
        </a>
      </p>
      <div className="text-red-500">
        {eltrPem?.ok === false && eltrPem.error}
      </div>
    </div>
  );
};

export default UploadPage;
