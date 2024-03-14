/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { ExemptionListTokenRequest } from "@securedna/frontend_common";
import { OrganismCard } from "./OrganismCard";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faWarning } from "@fortawesome/free-solid-svg-icons";

export interface EltrDetailProps {
  eltr: ExemptionListTokenRequest;
}

export const EltrDetail = (props: EltrDetailProps) => {
  const { eltr } = props;
  const requestorName = eltr.V1.requestor.name || "Anonymous";
  return (
    <div>
      <h2>Contact info</h2>
      <p className="my-2">The exemptions are requested by:</p>
      <dl className="ml-8">
        <dt className="font-bold hidden">Name</dt>
        <dd className="ml-4">{requestorName}</dd>
        <dt className="font-bold hidden">Phone number</dt>
        <dd className="ml-4">
          {eltr.V1.requestor.phone_number || "(no phone number given)"}
        </dd>
        <dt className="font-bold hidden">Email address</dt>
        <dd className="ml-4">
          {eltr.V1.requestor.email ? (
            <a href={"mailto:" + eltr.V1.requestor.email}>
              {eltr.V1.requestor.email}
            </a>
          ) : (
            "(no email given)"
          )}
        </dd>
        <dt className="font-bold hidden">ORCID</dt>
        <dd className="ml-4">
          {eltr.V1.requestor.orcid || "(no ORCID given)"}
        </dd>
      </dl>
      <h2>Shipping addresses</h2>
      <p className="my-2">
        The exemptions are only granted for shipments to one of these addresses:
      </p>
      <ul className="ml-12">
        {eltr.V1.shipping_addresses.map((address, i) => (
          <li key={i}>{address.join(", ")}</li>
        ))}
      </ul>
      <h2>Two-factor authentication</h2>
      {eltr.V1.requestor_auth_devices.length === 0 ? (
        <p className="my-2 py-4 px-6 bg-black/5 rounded-lg">
          <FontAwesomeIcon icon={faWarning} className="mr-2" />
          No two-factor authentication devices were provided by the requestor.
          SecureDNA requires two-factor authentication for exemption list
          tokens. Contact the requestor about making a new ELT request.
        </p>
      ) : (
        <>
          <p className="my-2">
            To use the token, a researcher will need to authenticate using one
            of the following devices:
          </p>
          <ul className="ml-12">
            {eltr.V1.requestor_auth_devices.map((device, i) => (
              <li key={i}>
                Yubikey: <b>{device.Yubikey.join("").toLowerCase()}</b>
              </li>
            ))}
          </ul>
        </>
      )}
      <h2>Exemptions</h2>
      <p className="my-2">
        Exemptions are requested for the following organisms:
      </p>
      <div>
        {eltr.V1.exemptions.map((organism, i) => (
          <OrganismCard key={i} organism={organism} />
        ))}
      </div>
    </div>
  );
};
