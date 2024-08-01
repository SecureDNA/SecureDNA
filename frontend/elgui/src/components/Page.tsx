/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { ReactNode } from "react";
import SecureDnaLogo from "./SecureDnaLogo";

export function Page(props: { title: string; children?: ReactNode }) {
  return (
    <div className="w-full flex flex-col items-center">
      <section className="w-full bg-primary text-center">
        <div className="max-w-3xl m-auto relative bg-primary px-2">
          <div className="flex items-center">
            <SecureDnaLogo />
            <h1>{props.title}</h1>
          </div>
        </div>
      </section>
      {props.children}
    </div>
  );
}
