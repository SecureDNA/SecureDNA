/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { ReactNode } from "react";

export function Card(props: { children: ReactNode }) {
  return (
    <div className="border border-primary bg-primary/10 rounded-lg max-w-screen-lg px-8 py-6 flex flex-col gap-4">
      {props.children}
    </div>
  );
}
