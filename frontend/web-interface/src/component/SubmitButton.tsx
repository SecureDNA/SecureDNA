/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/** Render a styled submit button, passing the props through to the underlying button */
export function SubmitButton(
  props: React.ButtonHTMLAttributes<HTMLButtonElement>,
) {
  return (
    <button
      className="block w-full bg-primary text-white font-bold mt-8 p-4 rounded-lg disabled:bg-black/10 disabled:text-black/20 transition-colors"
      type="button"
      {...props}
    >
      Submit
    </button>
  );
}
