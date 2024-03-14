/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

// Types for the web form.
// Underscores are used in field names to align with Rust/JSON formats.

import {
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
  /// An ISO 3166-1 Alpha-2 code.
  country: string;
  state: string | undefined;
  city: string | undefined;
  postalCode: string | undefined;
  streetAddress: string | undefined;
  organization: string | undefined;
}

export interface ExemptionList {
  organisms: OrganismWithSource[];
  shippingAddresses: ShippingAddress[];
  requestor: Description;
  authenticators: Authenticator[];
}

export interface ExemptionListFormData extends ExemptionList {
  /// Used implicitly by Formik in <FastaField />.
  fastaEditor: string;
}

export const emptyShippingAddress: ShippingAddress = {
  country: "",
  state: "",
  city: "",
  postalCode: "",
  streetAddress: "",
  organization: "",
};

export const emptyExemptionListFormData: ExemptionListFormData = {
  organisms: [{ name: "", sequences: [] }],
  shippingAddresses: [emptyShippingAddress],
  requestor: { name: "", email: "", phone_number: "", orcid: "" },
  authenticators: [],
  fastaEditor: "",
};
