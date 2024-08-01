/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import type { ReactNode } from "react";
import colors from "tailwindcss/colors";

interface UrlWarningProps {
  setSynthClientUrl: (url: string) => void;
  synthClientUrl: string | null;
}

function Warning({ children }: { children: ReactNode }) {
  return (
    <div className="text-sm">
      <FontAwesomeIcon icon={faWarning} color={colors.yellow[500]} /> {children}
    </div>
  );
}

export default function UrlWarning({
  setSynthClientUrl,
  synthClientUrl,
}: UrlWarningProps) {
  const match = synthClientUrl?.match(/\/v[0-9]+\//);
  return match ? (
    <Warning>
      This isn't the base URL – try{" "}
      <button
        type="button"
        className="text-blue-500 hover:underline"
        onClick={() =>
          setSynthClientUrl((synthClientUrl ?? "").replace(/\/v[0-9]+.*/, ""))
        }
      >
        removing "{match[0]}" and everything after.
      </button>
    </Warning>
  ) : synthClientUrl?.includes("http:") && location.protocol === "https:" ? (
    <Warning>
      This page is served over HTTPS, so connecting to an HTTP synthclient will
      not work. You should host synthclient using HTTPS.
    </Warning>
  ) : undefined;
}
