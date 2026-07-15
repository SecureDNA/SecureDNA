/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { Description } from "..";

interface RequestorDetailProps {
  requestor: Description;
}

export function RequestorDetail({ requestor }: RequestorDetailProps) {
  const requestorName = requestor.name || "Anonymous";

  return (
    <>
      <dl className="ml-8">
        <dt className="font-bold hidden">Name</dt>
        <dd className="ml-4">{requestorName}</dd>
        <dt className="font-bold hidden">Phone number</dt>
        <dd className="ml-4">
          {requestor.phone_number ? (
            <a href={`tel:${requestor.phone_number}`}>
              {requestor.phone_number}
            </a>
          ) : (
            "(no phone number given)"
          )}
        </dd>
        <dt className="font-bold hidden">Email address</dt>
        <dd className="ml-4">{requestor.email || "(no email given)"}</dd>
        <dt className="font-bold hidden">ORCID</dt>
        <dd className="ml-4">
          {requestor.orcid ? (
            <a
              href={`https://orcid.org/${encodeURIComponent(requestor.orcid)}`}
            >
              {requestor.orcid}
            </a>
          ) : (
            "(no ORCID given)"
          )}
        </dd>
      </dl>
    </>
  );
}
