/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { ExemptionTokenRequest, Result } from "@securedna/frontend_common";
import { useCallback } from "react";
import { DragUpload } from "src/components/DragUpload";
import { etrPemToJsObject } from "src/util/sign_etr";
import { useApprovalStore } from "./store";

const UploadPage = () => {
  const setEtr = useApprovalStore((state) => state.setEtr);
  const setEtrPem = useApprovalStore((state) => state.setEtrPem);
  const advance = useApprovalStore((state) => state.advance);

  const upload = useCallback(
    (
      etr: ExemptionTokenRequest | undefined,
      etrPem: Result<Uint8Array, string>,
    ) => {
      setEtr(etr);
      setEtrPem(etrPem);
      if (etr && etrPem.ok) {
        advance();
      }
    },
    [setEtr, setEtrPem, advance],
  );

  const handleFile = (result: ArrayBuffer | undefined) => {
    if (result) {
      const pem = new Uint8Array(result);
      try {
        const json = etrPemToJsObject(pem);
        upload(json, { ok: true, value: pem });
      } catch (e) {
        upload(undefined, {
          ok: false,
          error: `Could not parse exemption token request file: ${e}`,
        });
      }
    } else {
      upload(undefined, {
        ok: false,
        error: "Could not parse exemption token request file.",
      });
    }
  };

  const etrPem = useApprovalStore((state) => state.etrPem);

  return (
    <div>
      <h2>About this tool</h2>
      <p className="mb-4">
        This tool allows an authorized party to approve a researcher’s request
        for DNA screening exemptions.
      </p>
      <p className="mb-4">
        Select an <b>.etr</b> file ("exemption token request") to get started.
      </p>
      <p className="my-4 flex justify-center">
        <DragUpload accept=".etr" onFile={handleFile} />
      </p>
      <p>
        Researchers can create .etr files using the{" "}
        <a href="./request">exemption request tool</a>.
      </p>
      <div className="text-red-500">{etrPem?.ok === false && etrPem.error}</div>
    </div>
  );
};

export default UploadPage;
