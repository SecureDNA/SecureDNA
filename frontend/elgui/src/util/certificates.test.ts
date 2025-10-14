/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { describe, expect, test } from "vitest";

import fs from "node:fs";
import path from "node:path";

import { TextDecoder } from "node:util";
import type { Exemption, OrganismWithSource } from "src/types";
import {
  etBundlePemToJsObject,
  etrPemToJsObject,
  makeEtrPem,
  signEtr,
} from "./sign_etr";

const exemptionLeafCert = fs.readFileSync(
  path.resolve(__dirname, "../../../../test/certs/exemption-leaf.cert"),
  { encoding: "utf-8" },
);

const exemptionLeafPriv = fs.readFileSync(
  path.resolve(__dirname, "../../../../test/certs/exemption-leaf.priv"),
  { encoding: "utf-8" },
);

const organism: OrganismWithSource = {
  name: "Test organism",
  sequences: [
    {
      source: "",
      Dna: {
        records: [
          { contents: "ACGTACGTACGTACGT", header: "", line_range: [1, 2] },
        ],
      },
    },
  ],
};

const testEl: Exemption = {
  publicKey: undefined,
  organisms: [organism],
  shippingAddresses: [
    {
      id: "a1b2c3d4",
      country: "US",
      city: "Test City",
      postalCode: "12345",
      state: "NY",
      streetAddress: "111 Test Drive",
      organization: "",
    },
  ],
  requestor: {
    name: "John Doe",
    email: "j@example.com",
    phone_number: "+12223334444",
    orcid: "0000-0002-1825-0097",
  },
  authenticators: [{ Yubikey: "cccjgjgkhcbb" }],
  attachments: [{ name: "Test attachment", contents: [1, 2, 3] }],
};

describe("certificates bindings", () => {
  test("creates an exemption token request PEM that roundtrips", () => {
    const pem = makeEtrPem(testEl);
    const pemText = new TextDecoder().decode(pem);
    expect(pemText).toMatch("-BEGIN SECUREDNA EXEMPTION TOKEN REQUEST-");

    const result = etrPemToJsObject(pem);
    if (!result.ok) throw new Error("Decoding ETR PEM failed in test");
    const json = result.value;

    json.V1.request_id = [];
    expect(json).toMatchInlineSnapshot(`
      {
        "V1": {
          "attachments": [
            {
              "contents": [
                1,
                2,
                3,
              ],
              "name": "Test attachment",
            },
          ],
          "exemptions": [
            {
              "name": "Test organism",
              "sequences": [
                {
                  "Dna": {
                    "records": [
                      {
                        "contents": "ACGTACGTACGTACGT",
                        "header": "",
                        "line_range": [
                          1,
                          2,
                        ],
                      },
                    ],
                  },
                },
              ],
            },
          ],
          "guard": "ETR1",
          "public_key": undefined,
          "request_id": [],
          "requestor": {
            "email": "j@example.com",
            "name": "John Doe",
            "orcid": "0000-0002-1825-0097",
            "phone_number": "+12223334444",
          },
          "requestor_auth_devices": [
            {
              "Yubikey": "cccjgjgkhcbb",
            },
          ],
          "reserved": "",
          "shipping_addresses": [
            [
              "111 Test Drive",
              "Test City, NY 12345",
              "United States of America",
            ],
          ],
        },
      }
    `);
  });

  test("creates an exemption token", () => {
    const etrPem = makeEtrPem(testEl);
    const certPem = new TextEncoder().encode(exemptionLeafCert);
    const privateKeyPem = new TextEncoder().encode(exemptionLeafPriv);
    const et = signEtr({
      etrPem,
      certPem,
      privateKeyPem,
      validityDays: 5,
      passphrase: "test",
      screenedExemptions: [],
    });
    const etPem = new TextDecoder().decode(et);
    expect(etPem).toMatch("-BEGIN SECUREDNA EXEMPTION TOKEN-");

    const result = etBundlePemToJsObject(et);
    if (!result.ok) throw new Error("Decoding ET PEM failed in test");
    const json = result.value;

    json.V1.data.issuer_fields.expiration = {
      not_valid_before: 0,
      not_valid_after: 0,
    };
    json.V1.data.issuer_fields.issuance_id = [];
    json.V1.data.request.request_id = [];
    json.V1.signature = [];
    expect(json).toMatchInlineSnapshot(`
      {
        "V1": {
          "data": {
            "issuer_fields": {
              "emails_to_notify": [],
              "expiration": {
                "not_valid_after": 0,
                "not_valid_before": 0,
              },
              "guard": "ELTI1",
              "identity": {
                "desc": "SecureDNA-exemption-leaf, ca-exemption-leaf@securedna.org",
                "pk": "2505bc916dd1b6fceacaf37677d8374bae9ed48461de8ffb161cef00632be5a7",
              },
              "issuance_id": [],
              "issuer_auth_devices": [],
            },
            "request": {
              "attachments": [
                {
                  "contents": [
                    1,
                    2,
                    3,
                  ],
                  "name": "Test attachment",
                },
              ],
              "exemptions": [
                {
                  "name": "Test organism",
                  "sequences": [
                    {
                      "Dna": {
                        "records": [
                          {
                            "contents": "ACGTACGTACGTACGT",
                            "header": "",
                            "line_range": [
                              1,
                              2,
                            ],
                          },
                        ],
                      },
                    },
                  ],
                },
              ],
              "guard": "ETR1",
              "public_key": undefined,
              "request_id": [],
              "requestor": {
                "email": "j@example.com",
                "name": "John Doe",
                "orcid": "0000-0002-1825-0097",
                "phone_number": "+12223334444",
              },
              "requestor_auth_devices": [
                {
                  "Yubikey": "cccjgjgkhcbb",
                },
              ],
              "reserved": "",
              "shipping_addresses": [
                [
                  "111 Test Drive",
                  "Test City, NY 12345",
                  "United States of America",
                ],
              ],
            },
          },
          "signature": [],
        },
      }
    `);
  });
});
