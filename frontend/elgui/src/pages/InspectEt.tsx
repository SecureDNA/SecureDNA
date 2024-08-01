/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { ExemptionToken, Result } from "@securedna/frontend_common";
import type React from "react";
import { useState } from "react";
import { EtSummary, Page } from "src/components";
import { etBundlePemToJsObject } from "src/util/sign_etr";

export default function InspectEt() {
  const [etPem, setEtPem] = useState<Result<Uint8Array, string> | undefined>(
    undefined,
  );
  const [et, setEt] = useState<ExemptionToken | undefined>(undefined);

  const onUploadEt = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files?.[0]) {
      const reader = new FileReader();
      reader.onload = (loaded) => {
        const result = loaded.target?.result;
        if (result && result instanceof ArrayBuffer) {
          const pem = new Uint8Array(result);
          try {
            setEtPem({ ok: true, value: pem });
            const json = etBundlePemToJsObject(pem);
            setEt(json);
          } catch (e) {
            setEtPem({
              ok: false,
              error: `Could not parse exemption token file: ${e}`,
            });
            setEt(undefined);
          }
        } else {
          setEtPem({
            ok: false,
            error: "Could not parse exemption token file.",
          });
          setEt(undefined);
        }
      };
      reader.readAsArrayBuffer(event.target.files[0]);
    }
  };

  return (
    <Page title="Exemption Inspector">
      <div className="w-full max-w-3xl my-4">
        <h2>About this tool</h2>
        <p>You can use this tool to inspect an exemption token as JSON.</p>
        <p className="my-4">
          Upload an .et file:{" "}
          <input type="file" accept=".et" onChange={onUploadEt} />
        </p>
        {etPem &&
          (!etPem.ok ? (
            <p className="text-red-500">{etPem.error}</p>
          ) : !et ? (
            <p className="text-red-500">Failed to decode JSON</p>
          ) : (
            <EtSummary et={et} />
          ))}
      </div>
    </Page>
  );
}
