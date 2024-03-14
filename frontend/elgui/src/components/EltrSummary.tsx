/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  ExemptionListTokenRequest,
  copyToClipboard,
} from "@securedna/frontend_common";

export const EltrSummary = (props: { eltr: ExemptionListTokenRequest }) => {
  const { eltr } = props;
  const count = eltr.V1.exemptions.length;
  const exemptions = count === 1 ? "exemption" : "exemptions";
  const requestorName = eltr.V1.requestor.name || "Anonymous";

  return (
    <div>
      <b>{requestorName}</b> is requesting {count} {exemptions}.
      <button
        type="button"
        className="ml-2 bg-gray-200 px-2 py-1 rounded hover:bg-gray-300 text-sm"
        onClick={() =>
          copyToClipboard("ELTR JSON", JSON.stringify(eltr, null, 2))
        }
      >
        Copy as JSON
      </button>
    </div>
  );
};
