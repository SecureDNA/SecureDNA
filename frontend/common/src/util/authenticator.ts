/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { Authenticator } from "..";

export function authenticatorName(authenticator: Authenticator): string {
  return "Yubikey" in authenticator ? "Yubikey" : "TOTP";
}

export function authenticatorCode(authenticator: Authenticator): string {
  return "Yubikey" in authenticator
    ? authenticator.Yubikey
    : authenticator.Totp;
}
