/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type React from "react";
import { twMerge } from "tailwind-merge";

export const Button = (
  props: React.ComponentPropsWithoutRef<"button"> & {
    type: "button" | "submit";
  },
) => (
  <button
    {...props}
    className={twMerge(
      "enabled:border rounded-lg shrink-0 border-secondary enabled:hover:bg-secondary enabled:hover:cursor-pointer enabled:hover:text-white enabled:hover:opacity-90 py-2 px-4 transition disabled:bg-black/10 disabled:text-black/20",
      props.className,
    )}
  />
);
