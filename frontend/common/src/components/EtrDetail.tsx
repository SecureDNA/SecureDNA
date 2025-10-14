/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { type ExemptionTokenRequest, copyToClipboard } from "..";
import { authenticatorCode, authenticatorName } from "../util/authenticator";
import { InspectAttachment } from "./InspectAttachment";
import { OrganismCard } from "./OrganismCard";

export interface EtrDetailProps {
  etr: ExemptionTokenRequest;
}

export const EtrDetail = (props: EtrDetailProps) => {
  const { etr } = props;
  const requestorName = etr.V1.requestor.name || "Anonymous";
  return (
    <div>
      <h1>
        Exemption Token Request{" "}
        <button
          type="button"
          className="bg-gray-200 px-2 py-1 ml-2 rounded-sm hover:bg-gray-300 text-sm"
          onClick={() =>
            copyToClipboard("exemption JSON", JSON.stringify(etr, null, 2))
          }
        >
          Copy as JSON
        </button>
      </h1>
      <h2>Contact info</h2>
      <p className="my-2">The exemptions are requested by:</p>
      <dl className="ml-8">
        <dt className="font-bold hidden">Name</dt>
        <dd className="ml-4">{requestorName}</dd>
        <dt className="font-bold hidden">Phone number</dt>
        <dd className="ml-4">
          {etr.V1.requestor.phone_number ? (
            <a href={`tel:${etr.V1.requestor.phone_number}`}>
              {etr.V1.requestor.phone_number}
            </a>
          ) : (
            "(no phone number given)"
          )}
        </dd>
        <dt className="font-bold hidden">Email address</dt>
        <dd className="ml-4">{etr.V1.requestor.email || "(no email given)"}</dd>
        <dt className="font-bold hidden">ORCID</dt>
        <dd className="ml-4">
          {etr.V1.requestor.orcid ? (
            <a
              href={`https://orcid.org/${encodeURIComponent(etr.V1.requestor.orcid)}`}
            >
              {etr.V1.requestor.orcid}
            </a>
          ) : (
            "(no ORCID given)"
          )}
        </dd>
      </dl>
      <h2>Shipping addresses</h2>
      <p className="my-2">
        The exemptions are only granted for shipments to one of these addresses:
      </p>
      <ul className="ml-12">
        {etr.V1.shipping_addresses.map((address, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
          <li key={i}>{address.join(", ")}</li>
        ))}
      </ul>
      {etr.V1.public_key && (
        <>
          <h2>Public key</h2>
          <p className="my-2">
            The following public key is attached to the exemption token request.
            The requestor can use the corresponding private key to make subsets
            of this token.
          </p>
          <pre className="ml-12">{etr.V1.public_key}</pre>
        </>
      )}
      <h2>Two-factor authentication</h2>
      {etr.V1.requestor_auth_devices.length === 0 ? (
        <p className="my-2 py-4 px-6 bg-primary/10 border-primary border rounded-lg">
          <FontAwesomeIcon icon={faWarning} className="mr-2" />
          No two-factor authentication devices were provided by the requestor.
          SecureDNA requires two-factor authentication for exemption tokens.
          Contact the requestor about making a new exemption token request.
        </p>
      ) : (
        <>
          <p className="my-2">
            To use the token, a researcher will need to authenticate using one
            of the following devices:
          </p>
          <ul className="ml-12">
            {etr.V1.requestor_auth_devices.map((device, i) => (
              <li key={JSON.stringify(device)}>
                {authenticatorName(device)}: <b>{authenticatorCode(device)}</b>
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
        {etr.V1.exemptions.map((organism, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
          <OrganismCard key={i} organism={organism} />
        ))}
      </div>
      {etr.V1.attachments.length > 0 && (
        <>
          <h2>Attachments</h2>
          <p className="my-2">
            The following additional documents are attached to this request:
          </p>
          <ul>
            {etr.V1.attachments.map((attachment, i) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: static data
              <li className="list-disc ml-8" key={i}>
                <InspectAttachment attachment={attachment} />
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
};
