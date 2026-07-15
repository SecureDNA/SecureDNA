/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type {
  ApiResponse,
  BundleCheckResult,
  CertCheckResult,
  Organism,
} from "@securedna/frontend_common";

export const exampleOrganism: Organism = {
  name: "Example organism",
  sequences: [
    { Id: "N23456" },
    {
      Dna: {
        records: [
          {
            header: "Example DNA record",
            contents: "ACTG".repeat(102),
            line_range: [1, 10],
          },
        ],
      },
    },
  ],
};

export const exampleScreeningResult: ApiResponse = {
  synthesis_permission: "denied",
  hits_by_record: [
    {
      fasta_header: "Sample",
      line_number_range: [1, 12],
      sequence_length: 404,
      hits_by_hazard: [
        {
          type: "nuc",
          is_wild_type: null,
          hit_regions: [
            {
              seq: "ACTG".repeat(20),
              seq_range_start: 20 * 4,
              seq_range_end: 40 * 4,
            },
          ],
          most_likely_organism: {
            name: "Exampleitis",
            organism_type: "Virus",
            ans: ["EX123.45"],
            tags: [],
          },
          organisms: [],
        },
        {
          type: "nuc",
          is_wild_type: null,
          hit_regions: [
            {
              seq: "ACTG".repeat(20),
              seq_range_start: 35 * 4,
              seq_range_end: 55 * 4,
            },
          ],
          most_likely_organism: {
            name: "Exampleitis",
            organism_type: "Virus",
            ans: ["EX123.45"],
            tags: [],
          },
          organisms: [],
        },
        {
          type: "nuc",
          is_wild_type: null,
          hit_regions: [
            {
              seq: "ACTG".repeat(20),
              seq_range_start: 45 * 4,
              seq_range_end: 65 * 4,
            },
          ],
          most_likely_organism: {
            name: "Otheritis",
            organism_type: "Virus",
            ans: ["O789"],
            tags: [],
          },
          organisms: [],
        },
      ],
    },
  ],
};

export const exampleAuthFeedback: Array<{
  label: string;
  value: BundleCheckResult | CertCheckResult | "loading";
}> = [
  { label: "Loading", value: "loading" },
  { label: "Could not parse key", value: { Err: "CouldNotParseKey" } },
  { label: "Incorrect password", value: { Err: "IncorrectPassword" } },
  { label: "Key mismatch", value: { Err: "KeyMismatch" } },
  { label: "Missing cert", value: { Err: "MissingCert" } },
  { label: "No key", value: { Err: "NoKey" } },
  { label: "Ok", value: { Ok: undefined } },
  { label: "Empty chain", value: { Err: { Chain: [] } } },
  {
    label: "Chain",
    value: {
      Err: {
        Chain: [
          {
            digest: {
              Certificate: {
                version: "Intermediate V1 Infrastructure",
                issued_to: {
                  pk: [...Array(32).keys()],
                  desc: "Issued to",
                },
                request_id: [...Array(16).keys()],
                issued_by: {
                  pk: [...Array(32).keys()],
                  desc: "Issued by",
                },
                issuance_id: [...Array(16).keys()],
                expiration: {
                  not_valid_before: 1717675210,
                  not_valid_after: 1720094410,
                },
                signature: [...Array(64).keys()],
                emails_to_notify: ["example@securedna.org"],
                auth_token: { Totp: "example-totp-token" },
              },
            },
            error: {
              causes: ["Revoked", "SignatureFailure"],
            },
          },
        ],
      },
    },
  },
];
