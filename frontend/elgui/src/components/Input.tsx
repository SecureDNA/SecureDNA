/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type React from "react";
import { twMerge } from "tailwind-merge";

export const Input = (props: React.ComponentPropsWithoutRef<"input">) => (
  <input
    {...props}
    className={twMerge(
      "block w-full border border-gray-200 outline-blue-500 p-2 rounded disabled:opacity-50",
      props.className,
    )}
  />
);
