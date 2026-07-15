/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { SynthesizerTokenFiles } from "@securedna/frontend_common";
import { create_synthesizer_token } from "certificates_wasm";

export type TokenPurpose = "centralized" | "benchtop" | "screening";

export type AuditKeySource = "new" | "existing";

export function defaultPurpose(): TokenPurpose {
  switch (new URLSearchParams(window.location.search).get("purpose")) {
    case "benchtop":
      return "benchtop";
    case "screening":
      return "screening";
    default:
      return "centralized";
  }
}

export interface FormValues {
  purpose: TokenPurpose;
  certPassphrase: string;
  domain: string;
  model: string;
  serial: string;
  rateLimit: string;
  tokenPassphrase: string;
  confirmTokenPassphrase: string;
  daysValid: string;
  auditEnabled: boolean;
  auditEmail: string | null;
  auditPassphrase: string | null;
  confirmAuditPassphrase: string | null;
  existingAuditPubPem: string | null;
}

export function submitSynthTokenForm(
  data: FormValues,
  certPem: string,
  privPem: string,
  auditKeySource: AuditKeySource,
  setError: (error: string) => void,
  setBusy: (busy: boolean) => void,
  setFiles: (files: SynthesizerTokenFiles | undefined) => void,
): void {
  if (!certPem) {
    setError("Upload a manufacturer cert.");
    return;
  }
  if (!privPem) {
    setError("Upload a manufacturer private key.");
    return;
  }
  if (data.tokenPassphrase !== data.confirmTokenPassphrase) {
    setError("New token passphrase does not match its confirmation.");
    return;
  }
  if (data.tokenPassphrase === data.certPassphrase) {
    setError("New token passphrase must not equal cert passphrase.");
    return;
  }
  if (data.tokenPassphrase.length < 10) {
    setError("New token passphrase should be at least 10 characters long.");
    return;
  }

  if (data.auditEnabled) {
    if (!data.auditEmail || !data.auditEmail.includes("@")) {
      setError("Enter a valid audit email.");
      return;
    }
    if (auditKeySource === "new") {
      // Then we need a valid new passphrase:
      if (!data.auditPassphrase) {
        setError("Enter a passphrase for a new audit keypair.");
        return;
      }
      if (data.auditPassphrase.length < 10) {
        setError("New audit passphrase should be at least 10 characters long.");
        return;
      }
      if (data.auditPassphrase !== data.confirmAuditPassphrase) {
        setError("New audit passphrase does not match its confirmation.");
        return;
      }
    }
  }
  setError("");
  setFiles(undefined);
  setBusy(true);
  setTimeout(() => {
    let files: SynthesizerTokenFiles;
    try {
      files = create_synthesizer_token({
        domain: data.domain,
        model:
          data.purpose === "screening"
            ? "{BSA}"
            : data.purpose === "centralized"
              ? ""
              : data.model,
        serial:
          data.purpose === "screening"
            ? "{BSA}"
            : data.purpose === "centralized"
              ? ""
              : data.serial,
        rate_limit: Number(data.rateLimit),
        audit_email: data.auditEmail,
        audit_passphrase: data.auditPassphrase ? data.auditPassphrase : null,
        token_passphrase: data.tokenPassphrase,
        cert_pem: certPem,
        cert_private_key_pem: privPem,
        cert_passphrase: data.certPassphrase,
        days_valid: Number(data.daysValid),
        existing_audit_pub_pem: data.existingAuditPubPem,
      });
    } catch (e) {
      setError(String(e));
      setBusy(false);
      return;
    }
    setFiles(files);
    setTimeout(() => {
      window.scrollTo(0, document.body.scrollHeight);
      setBusy(false);
    }, 0);
  }, 50);
}
