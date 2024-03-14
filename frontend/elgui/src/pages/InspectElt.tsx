/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { ExemptionListToken, Result } from "@securedna/frontend_common";
import React, { useState } from "react";
import { EltSummary, Page } from "src/components";
import { eltBundlePemToJsObject } from "src/util/sign_eltr";

interface InspectEltProps {}

export default function InspectElt(props: InspectEltProps) {
  const [eltPem, setEltPem] = useState<Result<Uint8Array, string> | undefined>(
    undefined
  );
  const [elt, setElt] = useState<ExemptionListToken | undefined>(undefined);

  const onUploadElt = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      const reader = new FileReader();
      reader.onload = (loaded) => {
        const result = loaded.target?.result;
        if (result && result instanceof ArrayBuffer) {
          const pem = new Uint8Array(result);
          try {
            setEltPem({ ok: true, value: pem });
            const json = eltBundlePemToJsObject(pem);
            setElt(json);
          } catch (e) {
            setEltPem({
              ok: false,
              error: "Could not parse ELT file: " + e,
            });
            setElt(undefined);
          }
        } else {
          setEltPem({
            ok: false,
            error: "Could not parse ELT file.",
          });
          setElt(undefined);
        }
      };
      reader.readAsArrayBuffer(event.target.files[0]);
    }
  };

  return (
    <Page title="ELT Inspection Tool">
      <div className="max-w-prose my-8">
        <p>You can use this tool to inspect an ELT as JSON.</p>
        <p className="my-4">
          Upload an .elt file:{" "}
          <input type="file" accept=".elt" onChange={onUploadElt} />
        </p>
        {eltPem &&
          (!eltPem.ok ? (
            <p className="text-red-500">{eltPem.error}</p>
          ) : !elt ? (
            <p className="text-red-500">Failed to decode JSON</p>
          ) : (
            <EltSummary elt={elt} />
          ))}
      </div>
    </Page>
  );
}
