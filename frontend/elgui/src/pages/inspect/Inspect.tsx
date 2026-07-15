/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  type AuthFileResult,
  EtDetail,
  EtrDetail,
  type ExemptionToken,
  type ExemptionTokenRequest,
  FileUpload,
  Page,
  type Result,
} from "@securedna/frontend_common";
import { useEffect, useState } from "react";
import { etBundlePemToJsObject, etrPemToJsObject } from "src/util/sign_etr";
import EsrDetail from "./EsrDetail";

type EncryptedScreeningResponse = { esrPem: string };
type Content =
  | EncryptedScreeningResponse
  | ExemptionToken
  | ExemptionTokenRequest;

function isEncryptedScreeningResponse(
  content: Content,
): content is EncryptedScreeningResponse {
  return "esrPem" in content;
}

function isEtr(etr: Content): etr is ExemptionTokenRequest {
  return "V1" in etr && "request_id" in etr.V1;
}

export default function Inspect() {
  const [uploaded, setUploaded] = useState<AuthFileResult>();
  const [decoded, setDecoded] = useState<Result<Content | undefined, string>>({
    ok: true,
    value: undefined,
  });

  useEffect(() => {
    let result: Result<Content | undefined, string>;
    if (!uploaded?.ok) {
      result = { ok: true, value: undefined };
    } else if (uploaded.value.name.endsWith(".esr")) {
      try {
        result = {
          ok: true,
          value: { esrPem: new TextDecoder().decode(uploaded.value.array) },
        };
      } catch (e) {
        result = {
          ok: false,
          error:
            "Failed to decode encrypted screening response as text. " +
            "(It should be a text file starting with: " +
            "-----BEGIN SECUREDNA ENCRYPTED SCREENING RESPONSE-----)",
        };
      }
    } else if (uploaded.value.name.endsWith(".et")) {
      result = etBundlePemToJsObject(uploaded.value.array);
    } else if (uploaded.value.name.endsWith(".etr")) {
      result = etrPemToJsObject(uploaded.value.array);
    } else {
      result = {
        ok: false,
        error: `Unknown file type: ${uploaded.value.name}`,
      };
    }
    setDecoded(result);
  }, [uploaded]);

  return (
    <Page title="Inspector">
      <div className="w-full max-w-3xl my-4">
        <h2>About this tool</h2>
        <p>You can use this tool to inspect SecureDNA files such as:</p>
        <ul className="my-4 ml-8 list-disc">
          <li>an exemption token (.et) or request file (.etr);</li>
          <li>an encrypted screening report (.esr).</li>
        </ul>
        <FileUpload
          header={"-----BEGIN SECUREDNA"}
          pem={uploaded}
          setPem={setUploaded}
          label={"Choose a file to inspect"}
          noun={"file"}
          acceptExtension={".et,.etr,.esr"}
        />
        {uploaded &&
          (!uploaded.ok ? (
            <p className="text-red-500">{uploaded.error}</p>
          ) : !decoded.ok ? (
            <p className="text-red-500">{decoded.error}</p>
          ) : (
            decoded.value &&
            (isEncryptedScreeningResponse(decoded.value) ? (
              <EsrDetail esrPem={decoded.value.esrPem} />
            ) : isEtr(decoded.value) ? (
              <EtrDetail etr={decoded.value} />
            ) : (
              <EtDetail et={decoded.value} />
            ))
          ))}
        <div className="mt-20" />
      </div>
    </Page>
  );
}
