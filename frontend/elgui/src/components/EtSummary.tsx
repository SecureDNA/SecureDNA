/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { CopyableCode, type ExemptionToken } from "@securedna/frontend_common";

interface EtSummaryProps {
  et: ExemptionToken;
}

export const EtSummary = ({ et }: EtSummaryProps) => {
  const count = et?.V1.data.request.exemptions.length;
  const exemptions = count === 1 ? "exemption" : "exemptions";
  const requestorName = et?.V1.data.request.requestor.name ?? "Anonymous";
  const validFrom = new Date(
    et?.V1.data.issuer_fields.expiration.not_valid_before * 1000,
  );
  const validUntil = new Date(
    et?.V1.data.issuer_fields.expiration.not_valid_after * 1000,
  );
  const options: Intl.DateTimeFormatOptions = {
    dateStyle: "long",
    timeStyle: "long",
    timeZone: "UTC",
  };

  return (
    <div>
      <h2>Summary</h2>
      <ul className="border bg-white rounded p-4">
        <li>
          Grants {count} {exemptions} for <b>{requestorName}</b>.
        </li>
        <li>
          <b>Valid from:</b> {validFrom.toLocaleString("en-US", options)}
        </li>
        <li>
          <b>Valid until:</b> {validUntil.toLocaleString("en-US", options)}
        </li>
      </ul>
      <h2>JSON data</h2>
      <CopyableCode
        description="exemption JSON"
        text={JSON.stringify(et, undefined, 2)}
      />
    </div>
  );
};
