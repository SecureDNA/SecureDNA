/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { describe, expect, test } from "vitest";
import { isOrcidChecksumValid } from "./orcid";

describe("isOrcidChecksumValid", () => {
  test("validates only a correct checksum digit", () => {
    // The documentation uses 0000-0001-5000-0007 as a valid example ORCID,
    // so that one should validate, and changing the last digit should fail.
    expect(isOrcidChecksumValid("0000-0001-5000-0000")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-0001")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-0002")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-0003")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-0004")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-0005")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-0006")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-0007")).toEqual(true);
    expect(isOrcidChecksumValid("0000-0001-5000-0008")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-0009")).toEqual(false);
    expect(isOrcidChecksumValid("0000-0001-5000-000X")).toEqual(false);

    // https://en.wikipedia.org/wiki/Josiah_S._Carberry
    expect(isOrcidChecksumValid("0000-0002-1825-0097")).toEqual(true);
    expect(isOrcidChecksumValid("0000-0002-1826-0097")).toEqual(false);

    // https://en.wikipedia.org/wiki/Stephen_Hawking
    expect(isOrcidChecksumValid("0000-0002-9079-593X")).toEqual(true);
    expect(isOrcidChecksumValid("0000-0020-9079-593X")).toEqual(false);

    // https://en.wikipedia.org/wiki/Kevin_M._Esvelt
    expect(isOrcidChecksumValid("0000-0001-8797-3945")).toEqual(true);
    expect(isOrcidChecksumValid("0000-0001-7978-3945")).toEqual(false);
  });
});
