/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { AuthFileResult, Result } from "@securedna/frontend_common";
import { useMemo, useState } from "react";
import { AuthCard } from "src/components/AuthCard";
import { CheckSubject } from "src/util/checkCert";
import { decryptEncryptedScreeningResponse } from "src/util/sign_etr";

export default function EsrDetail({ esrPem }: { esrPem: string }) {
  const [privPem, setPrivPem] = useState<AuthFileResult>();
  const [passphrase, setPassphrase] = useState("");
  const [validationState, setValidationState] = useState<
    "unfilled" | "error" | "ok"
  >("unfilled");

  const decrypted: Result<Uint8Array, string> | undefined = useMemo(() => {
    if (validationState === "unfilled") return undefined;
    if (validationState === "error")
      return { ok: false, error: "Error uploading private key" };
    if (!privPem) return { ok: false, error: "No private key selected" };
    if (!privPem.ok) return { ok: false, error: privPem.error };
    let eciesPem: string;
    try {
      eciesPem = new TextDecoder().decode(privPem.value.array);
    } catch (e) {
      return {
        ok: false,
        error: "ECIES private key is not a valid text file",
      };
    }
    try {
      const result = decryptEncryptedScreeningResponse(
        esrPem,
        eciesPem,
        passphrase,
      );
      return { ok: true, value: result };
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  }, [esrPem, privPem, passphrase, validationState]);

  return (
    <div>
      <AuthCard
        className="flex-1 w-[50%]"
        number={undefined}
        title={"ECIES private key"}
        noun="screening response"
        description={"Authenticate yourself to decrypt this screening response"}
        header="-----BEGIN SECUREDNA ENCRYPTED SCREENING RESPONSE-----"
        acceptExtension={".esr"}
        setPem={undefined}
        pem={undefined}
        setPrivPem={setPrivPem}
        privPem={privPem}
        passphrase={passphrase}
        setPassphrase={setPassphrase}
        setValidationState={setValidationState}
        checkSubject={CheckSubject.EciesPrivateKey}
      />

      {!decrypted
        ? undefined
        : decrypted.ok
          ? new TextDecoder().decode(decrypted.value)
          : decrypted.error}
    </div>
  );
}
