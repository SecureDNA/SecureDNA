/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

export function Spinner() {
  return (
    <div role="status">
      <svg
        aria-hidden="true"
        className="h-12 w-12 my-6 animate-spin"
        viewBox="0 0 12 12"
      >
        <path fill="none" stroke="#000000ff" d="M6,1a5,5,0,0,1,5,5" />
        <path fill="none" stroke="#00000020" d="M6,1a5,5,0,1,0,5,5" />
      </svg>
      <span className="sr-only">Loading...</span>
    </div>
  );
}
