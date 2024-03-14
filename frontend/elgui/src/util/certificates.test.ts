/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { describe, test, expect } from "vitest";

import { ExemptionList, OrganismWithSource } from "src/types";
import { TextDecoder } from "util";
import {
  eltBundlePemToJsObject,
  eltrPemToJsObject,
  makeEltrPem,
  signEltr,
} from "./sign_eltr";

const cert1234Pem: string = `-----BEGIN SECUREDNA EXEMPTION CERTIFICATE-----
MIIBWaKCAVUwggFRoIIBC6AHgAVMRUFGMYEJRVhFTVBUSU9OooH0oIGDgAhTVUJK
RUNUMYEQ/UgmvvEfZtvnF8iFRIYYRoIghZfkNj2cXtdTsDDM4rErJIb/K8pIos3I
ES+Z3na4HiajGoAESmFja4ESamFja0BzZWN1cmVkbmEub3JnpCcMEmJpbGxAc2Vj
dXJlZG5hLm9yZwwRYm9iQHNlY3VyZWRuYS5vcmehbIAHSVNTVUVSMYEQYfMPUCf4
6DXU0uTWnfSJh6I+gCAIEWRGwLD3YKNCOAhnx70ezVSKb7u9ykzmoPm/uuu9nIEa
SmFtZXMsIGphbWVzQHNlY3VyZWRuYS5vcmejDYAEZS21/4EFASEl0/+kAIFAYLRH
BqBaTNR5yYM8dzesiETrARChul/bQAYOaM+XjXACdWk+wuzGeCno548Nv90MWw1D
Dn9Rphco1XkIwBVZDA==
-----END SECUREDNA EXEMPTION CERTIFICATE-----

-----BEGIN SECUREDNA EXEMPTION CERTIFICATE CHAIN-----
MIIBMjCCAS6hggEqMIIBJqCB4aAGgARJTlQxgQlFWEVNUFRJT06igcugXoAIU1VC
SkVDVDGBEKkUFj8BD9oqD9vYT6EaBgyCIAgRZEbAsPdgo0I4CGfHvR7NVIpvu73K
TOag+b+6672coxyABUphbWVzgRNqYW1lc0BzZWN1cmVkbmEub3JnpAChaYAHSVNT
VUVSMYEQAG/157+Qkx8m9fdLXxi7nqI8gCDcrRCouTGnQlh2aLVkGgqpPPM1/FhO
xeRGQjPaFLyi34EYRnJhbiwgZnJhbkBzZWN1cmVkbmEub3JnowyABGUttfmBBGVS
n/mkAIFALmF19OEK3iKCwKmSD66LidBwO1wVpKCe9KThDA///EhPSTHq68jXT8Le
ERAvvFGsrxknK4+xbvFLns3TOiBYDw==
-----END SECUREDNA EXEMPTION CERTIFICATE CHAIN-----`;

const priv1234Pem: string = `-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----
MIHEMGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBC5ZZyZbMvcN74ds0Oo
FoiFAgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEE6RlXGs1nI7E+lb
MuKBkbMEYMT50QQ4Il2RO76+FyToMHvdBKVThU3dg0QBNBZPD/aLNdtjoqgHlMdx
aOhiVXfB3H97IQCDtyZiy1XGYEKJodSCpP17uYGf7yink/8o9bgdIH1Jvo0TCycF
dgJGjXsBrA==
-----END SECUREDNA ENCRYPTED PRIVATE KEY-----`;

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

const testEl: ExemptionList = {
  organisms: [organism],
  shippingAddresses: [
    {
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
  authenticators: [
    { Yubikey: ["C", "C", "C", "J", "G", "J", "G", "K", "H", "C", "B", "B"] },
  ],
};

describe("certificates bindings", () => {
  test("creates an ELTR PEM that roundtrips", () => {
    const pem = makeEltrPem(testEl);
    const pemText = new TextDecoder().decode(pem);
    expect(pemText).toMatch("-BEGIN SECUREDNA EXEMPTION LIST TOKEN REQUEST-");

    const json: any = eltrPemToJsObject(pem);
    delete json.V1.request_id;
    expect(json).toMatchInlineSnapshot(`
      {
        "V1": {
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
          "guard": "ELTR1",
          "requestor": {
            "email": "j@example.com",
            "name": "John Doe",
            "orcid": "0000-0002-1825-0097",
            "phone_number": "+12223334444",
          },
          "requestor_auth_devices": [
            {
              "Yubikey": [
                "C",
                "C",
                "C",
                "J",
                "G",
                "J",
                "G",
                "K",
                "H",
                "C",
                "B",
                "B",
              ],
            },
          ],
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

  test("creates an ELT", () => {
    const eltrPem = makeEltrPem(testEl);
    const certPem = new TextEncoder().encode(cert1234Pem);
    const privateKeyPem = new TextEncoder().encode(priv1234Pem);
    const elt = signEltr({
      eltrPem,
      certPem,
      privateKeyPem,
      validityDays: 5,
      passphrase: "1234",
      screenedExemptions: [],
    });
    const eltPem = new TextDecoder().decode(elt);
    expect(eltPem).toMatch("-BEGIN SECUREDNA EXEMPTION LIST TOKEN-");
    let json: any = eltBundlePemToJsObject(elt);
    delete json.V1.data.issuer_fields.expiration;
    delete json.V1.data.issuer_fields.issuance_id;
    delete json.V1.data.request.request_id;
    delete json.V1.signature;
    expect(json).toMatchInlineSnapshot(`
      {
        "V1": {
          "data": {
            "issuer_fields": {
              "emails_to_notify": [
                "bill@securedna.org",
                "bob@securedna.org",
              ],
              "guard": "ELTI1",
              "identity": {
                "desc": "Jack, jack@securedna.org",
                "pk": "8597e4363d9c5ed753b030cce2b12b2486ff2bca48a2cdc8112f99de76b81e26",
              },
              "issuer_auth_devices": [],
            },
            "request": {
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
              "guard": "ELTR1",
              "requestor": {
                "email": "j@example.com",
                "name": "John Doe",
                "orcid": "0000-0002-1825-0097",
                "phone_number": "+12223334444",
              },
              "requestor_auth_devices": [
                {
                  "Yubikey": [
                    "C",
                    "C",
                    "C",
                    "J",
                    "G",
                    "J",
                    "G",
                    "K",
                    "H",
                    "C",
                    "B",
                    "B",
                  ],
                },
              ],
              "shipping_addresses": [
                [
                  "111 Test Drive",
                  "Test City, NY 12345",
                  "United States of America",
                ],
              ],
            },
          },
        },
      }
    `);
  });
});
