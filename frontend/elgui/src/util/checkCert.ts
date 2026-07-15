/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type {
  BundleCheckError,
  CertBundlePreIssuanceError,
} from "@securedna/frontend_common";
import * as wasm from "certificates_wasm";

export type CertCheckResult =
  | { Ok: undefined }
  | { Err: CertBundlePreIssuanceError };

export type BundleCheckResult = { Ok: undefined } | { Err: BundleCheckError };

export enum CheckSubject {
  ManufacturerCert = "manufacturerCert",
  ExemptionCert = "exemptionCert",
  SynthToken = "synthToken",
  ExemptionToken = "exemptionToken",
  EciesPrivateKey = "eciesPrivateKey",
}

/**
 * Check the given cert and its passphrase.
 */
export function checkCert(
  pem: string | Uint8Array,
  privPem: string | Uint8Array,
  privPassphrase: string,
  subject: CheckSubject,
): CertCheckResult | BundleCheckResult {
  let pemString: string;
  if (typeof pem === "string") {
    pemString = pem;
  } else {
    try {
      pemString = new TextDecoder().decode(pem);
    } catch (_e) {
      return { Err: "CouldNotParseKey" };
    }
  }

  let privPemString: string;
  if (typeof privPem === "string") {
    privPemString = privPem;
  } else {
    try {
      privPemString = new TextDecoder().decode(privPem);
    } catch (_e) {
      return { Err: "CouldNotParseKey" };
    }
  }

  switch (subject) {
    case CheckSubject.ManufacturerCert:
      return wasm.check_manufacturer_cert(
        pemString,
        privPemString,
        privPassphrase,
      );
    case CheckSubject.ExemptionCert:
      return wasm.check_exemption_cert(
        pemString,
        privPemString,
        privPassphrase,
      );
    case CheckSubject.SynthToken:
      return wasm.check_synth_token(pemString, privPemString, privPassphrase);
    case CheckSubject.ExemptionToken:
      return wasm.check_exemption_token(
        pemString,
        privPemString,
        privPassphrase,
      );
    case CheckSubject.EciesPrivateKey:
      return wasm.check_ecies_private_key(
        pemString,
        privPemString,
        privPassphrase,
      );
  }
}
