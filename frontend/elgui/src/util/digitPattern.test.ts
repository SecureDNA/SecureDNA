/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { describe, expect, test } from "vitest";
import { fitToDigitPattern } from "./digitPattern";

describe("fitToDigitPattern", () => {
  test("fits digit strings to patterns", () => {
    expect(fitToDigitPattern("1234567", { pattern: "00-00-000" })).toEqual(
      "12-34-567"
    );
    expect(fitToDigitPattern("123456789", { pattern: "00-00-000" })).toEqual(
      "12-34-567"
    );
    expect(fitToDigitPattern("1234", { pattern: "00-00-000" })).toEqual(
      "12-34"
    );
    expect(fitToDigitPattern("2023 0830", { pattern: "0000/00/00" })).toEqual(
      "2023/08/30"
    );

    expect(fitToDigitPattern(" .12/34'[5", { pattern: "00(0)00" })).toEqual(
      "12(3)45"
    );
    expect(fitToDigitPattern("digit is 8 here", { pattern: "pat 0" })).toEqual(
      "pat 8"
    );
  });

  test("supports custom options", () => {
    expect(
      fitToDigitPattern("123xyaBc", {
        pattern: "00-00-00",
        digitRegex: /[0-9A-F]/gi,
        transform: "uppercase",
      })
    ).toEqual("12-3A-BC");
    expect(
      fitToDigitPattern("123xyaBc", {
        pattern: "00-00-00",
        digitRegex: /[0-9A-F]/gi,
        transform: "lowercase",
      })
    ).toEqual("12-3a-bc");
  });

  test("handles edge cases", () => {
    expect(fitToDigitPattern("", { pattern: "00-00" })).toEqual("");
    expect(fitToDigitPattern("123", { pattern: "" })).toEqual("");
    expect(fitToDigitPattern("", { pattern: "" })).toEqual("");
  });
});
