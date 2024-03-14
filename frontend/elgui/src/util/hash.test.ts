/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { describe, expect, test } from "vitest";
import { sha256 } from "./hash";

// Patch in crypto.subtle for the Node test environment.
const crypto = require("crypto");
Object.defineProperty(globalThis, "crypto", {
  value: {
    subtle: crypto.webcrypto.subtle,
  },
});

describe("sha256", () => {
  test("hashes correctly", async () => {
    expect(await sha256("")).toEqual(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    expect(await sha256("hello")).toEqual(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });
});
