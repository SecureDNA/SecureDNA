/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type React from "react";
import type { ReactNode } from "react";

export interface SettingProps {
  label: string;
  input: (props: React.HTMLAttributes<HTMLElement>) => ReactNode;
  children?: ReactNode;
  required?: boolean;
}

/** Render an input, and optional trailing children, in a styled settings card */
export function Setting(props: SettingProps) {
  return (
    <div className="flex flex-col py-2 sm:-inset-x-10">
      <label className="flex flex-col gap-1">
        <span className="text-gray-500">{props.label}</span>
        {props.input({
          "aria-required": props.required ?? false,
          className:
            "block w-full border border-gray-200 outline-blue-500 p-2 rounded disabled:opacity-50",
        })}
      </label>
      {props.children}
    </div>
  );
}
