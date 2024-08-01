/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

// Types for the web form.
// Underscores are used in field names to align with Rust/JSON formats.

import type {
  Authenticator,
  Description,
  GenbankId,
  Organism,
  Sequence,
} from "@securedna/frontend_common";

export type SequenceIdentifierWithSource =
  | { Dna: Sequence; source: string }
  | { Id: GenbankId };

export interface OrganismWithSource extends Organism {
  sequences: Array<SequenceIdentifierWithSource>;
}

export type FastaFile = Sequence;
export type FastaRecord = Sequence["records"][number];

export interface ShippingAddress {
  id: string;
  /// An ISO 3166-1 Alpha-2 code.
  country: string;
  state: string | undefined;
  city: string | undefined;
  postalCode: string | undefined;
  streetAddress: string | undefined;
  organization: string | undefined;
}

export interface Exemption {
  publicKey: string | undefined;
  organisms: OrganismWithSource[];
  shippingAddresses: ShippingAddress[];
  requestor: Description;
  authenticators: Authenticator[];
}

export interface ExemptionFormData extends Exemption {
  /// Used implicitly by Formik in <FastaField />.
  fastaEditor: string;
}

export function emptyShippingAddress(): ShippingAddress {
  return {
    id: crypto.randomUUID(),
    country: "",
    state: "",
    city: "",
    postalCode: "",
    streetAddress: "",
    organization: "",
  };
}

export function emptyExemptionFormData(): ExemptionFormData {
  return {
    publicKey: undefined,
    organisms: [{ name: "", sequences: [] }],
    shippingAddresses: [emptyShippingAddress()],
    requestor: { name: "", email: "", phone_number: "", orcid: "" },
    authenticators: [],
    fastaEditor: "",
  };
}
