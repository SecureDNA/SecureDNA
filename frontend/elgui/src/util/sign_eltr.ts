/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  Authenticator,
  ExemptionListToken,
  ExemptionListTokenRequest,
  GenbankId,
  ModhexCharacter,
  Organism,
  SequenceIdentifier,
  SignEltr,
} from "@securedna/frontend_common";
import * as wasm from "certificates_wasm";
import { enCountryDict } from "src/data/countries";
import {
  ExemptionList,
  OrganismWithSource,
  SequenceIdentifierWithSource,
  ShippingAddress,
} from "src/types";

const YUBIKEY_ID_LENGTH = 12;

export function parseYubikeyId(yubikeyId: string): Authenticator {
  const candidate = [...yubikeyId.toUpperCase()];
  if (yubikeyId.length !== YUBIKEY_ID_LENGTH) {
    throw new Error(
      `Invalid Yubikey ID length: ${yubikeyId.length} (should be ${YUBIKEY_ID_LENGTH})`
    );
  }

  for (const letter of candidate) {
    if ("CBDEFGHIJKLNRTUV".indexOf(letter) === -1) {
      throw new Error(`Invalid modhex character: ${letter}`);
    }
  }
  return { Yubikey: candidate as ModhexCharacter[] };
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

interface SignEltrFields {
  eltrPem: Uint8Array;
  certPem: Uint8Array;
  privateKeyPem: Uint8Array;
  passphrase: string;
  validityDays: number;
  screenedExemptions: GenbankId[];
}

function stripSource(
  sequence: SequenceIdentifierWithSource
): SequenceIdentifier {
  if ("Dna" in sequence) {
    return { Dna: sequence.Dna };
  } else {
    return sequence;
  }
}

function hasSequence(sequence: SequenceIdentifier): boolean {
  if ("Dna" in sequence) {
    return (
      sequence.Dna.records.reduce((a, b) => a + b.contents.length, 0) !== 0
    );
  } else {
    return true;
  }
}

function stripSources(organism: OrganismWithSource): Organism {
  return {
    ...organism,
    sequences: organism.sequences.filter(hasSequence).map(stripSource),
  };
}

/// Make an ELTR file in PEM format.
export function makeEltrPem(el: ExemptionList): Uint8Array {
  return wasm.make_eltr_v1_pem({
    exemptions: el.organisms.map(stripSources),
    requestor: el.requestor,
    requestor_auth_devices: el.authenticators,
    shipping_addresses: el.shippingAddresses.map(flattenShippingAddress),
  });
}

export function eltrPemToJsObject(pem: Uint8Array): ExemptionListTokenRequest {
  return wasm.eltr_pem_to_js_object(pem);
}

export function eltBundlePemToJsObject(pem: Uint8Array): ExemptionListToken {
  return wasm.elt_bundle_pem_to_js_object(pem);
}

function makeSignEltrBody(fields: SignEltrFields): SignEltr {
  return {
    eltr_pem: Array.from(fields.eltrPem),
    cert_pem: Array.from(fields.certPem),
    private_key_pem: Array.from(fields.privateKeyPem),
    passphrase: Array.from(new TextEncoder().encode(fields.passphrase)),
    validity_days: fields.validityDays,
  };
}

/// Sign an ELTR and get a ELT file in PEM format.
export function signEltr(fields: SignEltrFields): Uint8Array {
  const body = makeSignEltrBody(fields);
  return wasm.sign_eltr(body);
}
