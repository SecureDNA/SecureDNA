/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type React from "react";
import { twMerge } from "tailwind-merge";

export const PrimaryButton = (
  props: React.ComponentPropsWithoutRef<"button"> & {
    type: "button" | "submit";
  },
) => (
  <button
    {...props}
    className={twMerge(
      "bg-secondary font-medium enabled:hover:opacity-90 enabled:hover:cursor-pointer text-white disabled:bg-black/10 disabled:text-black/20 py-2 px-4 rounded-lg transition",
      props.className,
    )}
  />
);
