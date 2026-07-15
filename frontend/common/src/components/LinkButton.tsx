/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type React from "react";
import { twMerge } from "tailwind-merge";

export const LinkButton = (
  props: React.ComponentPropsWithoutRef<"button"> & {
    type: "button" | "submit";
  },
) => (
  <button
    {...props}
    className={twMerge(
      "underline enabled:hover:opacity-50 enabled:hover:cursor-pointer",
      props.className,
    )}
  />
);
