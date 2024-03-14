/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import React from "react";
import { twMerge } from "tailwind-merge";

export const Button = (props: React.ComponentPropsWithoutRef<"button">) => (
  <button
    {...props}
    className={twMerge(
      "enabled:border border-primary enabled:hover:bg-primary/10 text-primary py-2 px-4 rounded transition disabled:bg-black/10 disabled:text-black/20",
      props.className
    )}
  />
);
