/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { ReactNode } from "react";
import { Version } from "./Version";

export function Page(props: { title: string; children?: ReactNode }) {
  return (
    <div className="w-full flex flex-col items-center">
      <section className="w-full bg-gradient-to-br pt-10 from-primary-dark to-primary text-center text-white">
        <h1>{props.title}</h1>
        <Version />
      </section>
      {props.children}
    </div>
  );
}
