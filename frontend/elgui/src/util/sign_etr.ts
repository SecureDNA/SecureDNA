/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type {
  Authenticator,
  ExemptionToken,
  ExemptionTokenRequest,
  ExemptionTokenRequest1,
  GenbankId,
  Organism,
  PemKeyPair,
  SequenceIdentifier,
  SignEtr,
} from "@securedna/frontend_common";
import * as wasm from "certificates_wasm";
import { enCountryDict } from "src/data/countries";
import type {
  Exemption,
  OrganismWithSource,
  SequenceIdentifierWithSource,
  ShippingAddress,
} from "src/types";

const YUBIKEY_ID_LENGTH = 12;

export function parseYubikeyId(yubikeyId: string): Authenticator {
  const candidate = [...yubikeyId.toUpperCase()];
  if (yubikeyId.length !== YUBIKEY_ID_LENGTH) {
    throw new Error(
      `Invalid Yubikey ID length: ${yubikeyId.length} (should be ${YUBIKEY_ID_LENGTH})`,
    );
  }

  for (const letter of candidate) {
    if ("CBDEFGHIJKLNRTUV".indexOf(letter) === -1) {
      throw new Error(`Invalid modhex character: ${letter}`);
    }
  }
  return { Yubikey: yubikeyId.toLowerCase() };
}

function flattenShippingAddress({
  streetAddress,
  city,
  state,
  postalCode,
  country,
  organization,
}: ShippingAddress): string[] {
  const streetLines = (streetAddress ?? "").trim().split("\n");
  city ??= "";
  if (state) {
    city += (city ? ", " : "") + state;
  }
  if (postalCode) {
    city += (city ? " " : "") + postalCode;
  }
  const countryName = (enCountryDict[country] ?? "") as string;
  const parts = [organization ?? "", ...streetLines, city, countryName];
  return parts.filter((x) => x.trim());
}

interface SignEtrFields {
  etrPem: Uint8Array;
  certPem: Uint8Array;
  privateKeyPem: Uint8Array;
  passphrase: string;
  validityDays: number;
  screenedExemptions: GenbankId[];
}

function stripSource(
  sequence: SequenceIdentifierWithSource,
): SequenceIdentifier {
  if ("Dna" in sequence) {
    return { Dna: sequence.Dna };
  }
  return sequence;
}

function hasSequence(sequence: SequenceIdentifier): boolean {
  if ("Dna" in sequence) {
    return (
      sequence.Dna.records.reduce((a, b) => a + b.contents.length, 0) !== 0
    );
  }
  return true;
}

function stripSources(organism: OrganismWithSource): Organism {
  return {
    ...organism,
    sequences: organism.sequences.filter(hasSequence).map(stripSource),
  };
}

/**
 * Make an exemption token request file in PEM format.
 */
export function makeEtrPem(el: Exemption): Uint8Array {
  return wasm.make_etr_v1_pem({
    public_key_pem: el.publicKey,
    exemptions: el.organisms.map(stripSources),
    requestor: el.requestor,
    requestor_auth_devices: el.authenticators,
    shipping_addresses: el.shippingAddresses.map(flattenShippingAddress),
  });
}

/**
 * Convert an exemption token request to PEM format.
 */
export function etrToPem(
  etr: Omit<ExemptionTokenRequest1, "guard" | "request_id">,
): Uint8Array {
  return wasm.make_etr_v1_pem({
    public_key_pem: etr.public_key,
    exemptions: etr.exemptions,
    requestor: etr.requestor,
    requestor_auth_devices: etr.requestor_auth_devices,
    shipping_addresses: etr.shipping_addresses,
  });
}

export function etrPemToJsObject(pem: Uint8Array): ExemptionTokenRequest {
  return wasm.etr_pem_to_js_object(pem);
}

export function etBundlePemToJsObject(pem: Uint8Array): ExemptionToken {
  return wasm.et_bundle_pem_to_js_object(pem);
}

function makeSignEtrBody(fields: SignEtrFields): SignEtr {
  return {
    etr_pem: Array.from(fields.etrPem),
    cert_pem: Array.from(fields.certPem),
    private_key_pem: Array.from(fields.privateKeyPem),
    passphrase: Array.from(new TextEncoder().encode(fields.passphrase)),
    validity_days: fields.validityDays,
  };
}

/**
 * Sign an exemption token request and get a exemption token file in PEM format.
 */
export function signEtr(fields: SignEtrFields): Uint8Array {
  const body = makeSignEtrBody(fields);
  return wasm.sign_etr(body);
}

export interface SubsetEtFields {
  etPem: Uint8Array;
  etrPem: Uint8Array;
  privateKeyPem: Uint8Array;
  passphrase: string;
  validityDays: number;
}

/**
 * Subset an exemption token using an exemption token request.
 */
export function subsetEt(fields: SubsetEtFields): Uint8Array {
  return wasm.subset_et(
    fields.etPem,
    fields.etrPem,
    fields.privateKeyPem,
    new TextEncoder().encode(fields.passphrase),
    fields.validityDays,
  );
}

/**
 * Create a random keypair with the given passphrase.
 */
export function makeKeypair(passphrase: string): PemKeyPair {
  return wasm.make_keypair(passphrase);
}
