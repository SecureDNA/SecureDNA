/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

export function isOrcidChecksumValid(orcid: string): boolean {
  const digits = orcid.toUpperCase().replace(/[^0-9X]/g, "");
  if (digits.length !== 16) {
    return false;
  }
  // X should occur at the end, or not at all.
  const xIndex = digits.indexOf("X");
  if (xIndex !== 15 && xIndex !== -1) {
    return false;
  }

  // Recalculate the check digit, and compare it to the actual last digit.
  let total = 0;
  for (let i = 0; i < 15; i++) {
    total = (total + Number(digits[i])) * 2;
  }
  const remainder = total % 11;
  const result = (12 - remainder) % 11;
  const checkDigit = result === 10 ? "X" : String(result);
  return digits[15] === checkDigit;
}
