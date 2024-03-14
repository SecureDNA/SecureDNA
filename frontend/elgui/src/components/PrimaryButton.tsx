/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import React from "react";
import { twMerge } from "tailwind-merge";

export const PrimaryButton = (
  props: React.ComponentPropsWithoutRef<"button">
) => (
  <button
    {...props}
    className={twMerge(
      "bg-primary enabled:hover:bg-primary-light text-white disabled:bg-black/10 disabled:text-black/20 py-2 px-4 rounded transition",
      props.className
    )}
  />
);
