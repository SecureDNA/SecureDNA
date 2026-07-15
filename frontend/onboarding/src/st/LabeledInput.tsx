/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type React from "react";
import { type InputHTMLAttributes, forwardRef, useId } from "react";

type LabeledInputProps = {
  label: string;
} & InputHTMLAttributes<HTMLInputElement>;

const LabeledInput = forwardRef(
  (
    { label, type = "text", ...props }: LabeledInputProps,
    ref: React.ForwardedRef<HTMLInputElement>,
  ) => {
    const id = useId();

    return (
      <div className="flex flex-col gap-1">
        {/* biome-ignore lint/a11y/noLabelWithoutControl: false positive */}
        <label htmlFor={id}>{label}</label>
        <input id={id} type={type} ref={ref} className="input" {...props} />
      </div>
    );
  },
);

export default LabeledInput;
