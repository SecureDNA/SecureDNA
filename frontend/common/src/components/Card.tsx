/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { ReactNode } from "react";
import { twMerge } from "tailwind-merge";

export const Card = (props: {
  flavor?: "primary" | "warn";
  small?: boolean;
  className?: string;
  children: ReactNode;
}) => {
  const { flavor, small, children, className, ...rest } = props;
  return (
    <div
      {...rest}
      className={twMerge(
        "my-2 bg-white rounded-lg border",
        small ? "py-2 px-4" : "py-4 px-8",
        flavor === "primary"
          ? "bg-primary/10 border-primary"
          : flavor === "warn"
            ? "bg-warn/10 border-warn"
            : undefined,
        className,
      )}
    >
      {children}
    </div>
  );
};
