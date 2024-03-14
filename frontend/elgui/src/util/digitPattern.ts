/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/**
 * An object describing a pattern to fit digits to.
 */
export interface DigitPattern {
  /**
   * The pattern to fit to, like `000-000-000`.
   * `0` means a digit, and any other character is "punctuation".
   */
  pattern: string;
  /**
   * A global regex determining what to treat as a "digit".
   */
  digitRegex?: RegExp;
  /**
   * An optional transformation to apply to the input before fitting it to the pattern.
   */
  transform?: "uppercase" | "lowercase";
}

/**
 * Fit a string to a pattern of "digits" `0` and non-digit characters (such as hyphens or spaces).
 *
 * This is used in Input.tsx to fit the input into a format like "0000-0000-0000-0000" as the user types digits.
 *
 * @param input The input string, like `"12 3456789"`.
 * @param digitPattern An object describing the pattern to fit the digits into. For example, `{pattern: "000-000-000", digitRegex: /[0-9]/g}`
 * @returns The fitted string, like `"123-456-789"`.
 */
export function fitToDigitPattern(
  input: string,
  digitPattern: DigitPattern
): string {
  if (!input) return "";
  const { pattern, digitRegex, transform } = digitPattern;
  if (transform === "uppercase") {
    input = input.toUpperCase();
  } else if (transform === "lowercase") {
    input = input.toLowerCase();
  }
  const re = digitRegex ?? /[0-9]/g;
  const digits = [...input.matchAll(re)].join("");
  let i = 0;
  let output = "";
  for (const character of pattern) {
    if (character === "0") {
      output += digits[i++];
      if (i >= digits.length) break;
    } else {
      output += character;
    }
  }
  return output;
}
