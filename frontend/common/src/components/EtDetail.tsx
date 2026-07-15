/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { type ExemptionToken, copyToClipboard } from "..";
import { authenticatorCode, authenticatorName } from "../util/authenticator";
import { Card } from "./Card";
import { InspectAttachment } from "./InspectAttachment";
import { OrganismCard } from "./OrganismCard";
import { RequestorDetail } from "./RequestorDetail";

export interface EtDetailProps {
  et: ExemptionToken;
}

export const EtDetail = (props: EtDetailProps) => {
  const { et } = props;
  const { request, issuer_fields } = et.V1.data;

  // Convert second timestamps to milliseconds for new Date():
  const validFrom = new Date(issuer_fields.expiration.not_valid_before * 1000);
  const validUntil = new Date(issuer_fields.expiration.not_valid_after * 1000);

  const options: Intl.DateTimeFormatOptions = {
    dateStyle: "long",
    timeStyle: "long",
    timeZone: "UTC",
  };

  return (
    <div>
      <h1>
        Exemption Token{" "}
        <button
          type="button"
          className="bg-gray-200 px-2 py-1 ml-2 rounded-sm hover:bg-gray-300 text-sm"
          onClick={() =>
            copyToClipboard("exemption JSON", JSON.stringify(et, null, 2))
          }
        >
          Copy as JSON
        </button>
      </h1>
      <h2>Contact info</h2>
      <p className="my-2">The exemptions were requested by:</p>
      <RequestorDetail requestor={request.requestor} />

      <h2>Issuance</h2>
      <Card className="flex flex-col space-y-2">
        <p>
          Exemption granted by <b>{issuer_fields.identity.desc}</b>.
        </p>
        <p>
          Valid from: <b>{validFrom.toLocaleString("en-US", options)}</b>
        </p>
        <p>
          Valid until: <b>{validUntil.toLocaleString("en-US", options)}</b>
        </p>
      </Card>

      <h2>Shipping addresses</h2>
      <p className="my-2">
        The exemptions are only granted for shipments to one of these addresses:
      </p>
      <ul className="ml-12">
        {request.shipping_addresses.map((address, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
          <li key={i}>{address.join(", ")}</li>
        ))}
      </ul>
      {request.public_key && (
        <>
          <h2>Public key</h2>
          <p className="my-2">
            The following public key is attached to the exemption token request.
            The requestor can use the corresponding private key to make subsets
            of this token.
          </p>
          <pre className="ml-12">{request.public_key}</pre>
        </>
      )}
      <h2>Two-factor authentication</h2>
      {request.requestor_auth_devices.length === 0 ? (
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
            {request.requestor_auth_devices.map((device, i) => (
              <li key={JSON.stringify(device)}>
                {authenticatorName(device)}: <b>{authenticatorCode(device)}</b>
              </li>
            ))}
          </ul>
        </>
      )}
      <h2>Exemptions</h2>
      <p className="my-2">
        Exemptions are granted for the following organisms:
      </p>
      <div>
        {request.exemptions.map((organism, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
          <OrganismCard key={i} organism={organism} />
        ))}
      </div>
      {request.attachments.length > 0 && (
        <>
          <h2>Attachments</h2>
          <p className="my-2">
            The following additional documents were attached to this request:
          </p>
          <ul>
            {request.attachments.map((attachment, i) => (
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
