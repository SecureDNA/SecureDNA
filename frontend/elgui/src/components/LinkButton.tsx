/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import React from "react";
import { twMerge } from "tailwind-merge";

export const LinkButton = (props: React.ComponentPropsWithoutRef<"button">) => (
  <button
    {...props}
    className={twMerge(
      "text-primary hover:underline disabled:opacity-50",
      props.className
    )}
  />
);
