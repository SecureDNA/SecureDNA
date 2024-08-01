/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  type ExemptionTokenRequest,
  copyToClipboard,
} from "@securedna/frontend_common";

export const EtrSummary = (props: { etr: ExemptionTokenRequest }) => {
  const { etr } = props;
  const count = etr.V1.exemptions.length;
  const exemptions = count === 1 ? "exemption" : "exemptions";
  const requestorName = etr.V1.requestor.name || "Anonymous";

  return (
    <div>
      <b>{requestorName}</b> is requesting {count} {exemptions}.
      <button
        type="button"
        className="ml-2 bg-gray-200 px-2 py-1 rounded hover:bg-gray-300 text-sm"
        onClick={() =>
          copyToClipboard("exemption JSON", JSON.stringify(etr, null, 2))
        }
      >
        Copy as JSON
      </button>
    </div>
  );
};
