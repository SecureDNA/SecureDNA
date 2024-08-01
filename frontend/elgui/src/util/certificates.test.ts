/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { describe, expect, test } from "vitest";

import { TextDecoder } from "node:util";
import type {
  ExemptionToken,
  ExemptionTokenRequest,
  Expiration,
  Id,
  Signature,
} from "@securedna/frontend_common";
import type { Exemption, OrganismWithSource } from "src/types";
import {
  etBundlePemToJsObject,
  etrPemToJsObject,
  makeEtrPem,
  signEtr,
} from "./sign_etr";

const cert1234Pem: string = `-----BEGIN SECUREDNA EXEMPTION CERTIFICATE-----
MIIBZqKCAWIwggFeoIIBGKAHgAVMRUFGMYEJRVhFTVBUSU9OooIBAKCBj4ARRVhF
TVBUSU9OU1VCSkVDVDGBEH2isSL3AlXUZZg6D+t5sQCCIKQJCuWZRgfb7vnP9upJ
YUewga1ITmzHx0SjwRl01R0aoxqABEphY2uBEmphY2tAc2VjdXJlZG5hLm9yZ6Qn
DBJiaWxsQHNlY3VyZWRuYS5vcmcMEWJvYkBzZWN1cmVkbmEub3JnhQEAoWyAB0lT
U1VFUjGBEBbfpiDooxMyAm+aPVLChhSiPoAgRZ3zAm9LbmDH/mNHCvxfSUg1epzm
ywZ05H/hnlbVn7aBGkphbWVzLCBqYW1lc0BzZWN1cmVkbmEub3Jnow2ABGX+Z8GB
BQEh9oXBpACBQFSQYFzeC/t3YzPBOxk7vYLAdloT5nkajifzPjPOhT1ztlnL85Kq
BjAPwe3KrL+sLqKENxEENOxEM7Y5jMyRQwg=
-----END SECUREDNA EXEMPTION CERTIFICATE-----

-----BEGIN SECUREDNA EXEMPTION CERTIFICATE CHAIN-----
MIIBPjCCATqhggE2MIIBMqCB7aAGgARJTlQxgQlFWEVNUFRJT06igdegaoARRVhF
TVBUSU9OU1VCSkVDVDGBECDtc3kftVqNb1PX1OOYkGuCIEWd8wJvS25gx/5jRwr8
X0lINXqc5ssGdOR/4Z5W1Z+2oxyABUphbWVzgRNqYW1lc0BzZWN1cmVkbmEub3Jn
pACFAQChaYAHSVNTVUVSMYEQRJKrOx5j6IRTjanEd4pBPaI8gCCJmOdLRO1IN5iL
j7+6zkLYr4TNeWdvhvlLZOQgP8SaXoEYRnJhbiwgZnJhbkBzZWN1cmVkbmEub3Jn
owyABGX+Z7SBBGYjUbSkAIFAB1/9QSK1jo1rJZVqzyk2VxLxUquhSj5jdmWJqCPp
OvgMHHvi8lyXBhJfFkgBzjJAhmzdhZD28nWM/IMRLEb3DA==
-----END SECUREDNA EXEMPTION CERTIFICATE CHAIN-----`;

const priv1234Pem: string = `-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----
MIHEMGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBB/EEX9YGLjm3Du5m2U
rqVPAgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEAxEM8fbSGJHgcAJ
3huClX4EYBZo0rFJyrE+2+uAkaMaFIM/TSxsCrIFVWNzRMaGN90uYzfi/xNoJZ3E
g/GzY8X1FE+QZmfY1xXOzVFqaC89FYJ41qqXAAXWfZ8kCF98zATSZLJ2WHihDNI2
D1ibYopH3g==
-----END SECUREDNA ENCRYPTED PRIVATE KEY-----
`;

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
};

describe("certificates bindings", () => {
  test("creates an exemption token request PEM that roundtrips", () => {
    const pem = makeEtrPem(testEl);
    const pemText = new TextDecoder().decode(pem);
    expect(pemText).toMatch("-BEGIN SECUREDNA EXEMPTION TOKEN REQUEST-");

    const json: ExemptionTokenRequest = etrPemToJsObject(pem);
    json.V1.request_id = [];
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
    const certPem = new TextEncoder().encode(cert1234Pem);
    const privateKeyPem = new TextEncoder().encode(priv1234Pem);
    const et = signEtr({
      etrPem,
      certPem,
      privateKeyPem,
      validityDays: 5,
      passphrase: "1234",
      screenedExemptions: [],
    });
    const etPem = new TextDecoder().decode(et);
    expect(etPem).toMatch("-BEGIN SECUREDNA EXEMPTION TOKEN-");
    const json: ExemptionToken = etBundlePemToJsObject(et);
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
			        "emails_to_notify": [
			          "bill@securedna.org",
			          "bob@securedna.org",
			        ],
			        "expiration": {
			          "not_valid_after": 0,
			          "not_valid_before": 0,
			        },
			        "guard": "ELTI1",
			        "identity": {
			          "desc": "Jack, jack@securedna.org",
			          "pk": "a4090ae5994607dbeef9cff6ea496147b081ad484e6cc7c744a3c11974d51d1a",
			        },
			        "issuance_id": [],
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
