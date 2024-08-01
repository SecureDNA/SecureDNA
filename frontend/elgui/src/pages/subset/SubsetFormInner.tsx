/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  type Authenticator,
  type ExemptionToken,
  download,
  makeFileName,
} from "@securedna/frontend_common";
import update from "immutability-helper";
import { useState } from "react";
import { PrimaryButton } from "src/components";
import { AuthenticatorsInput } from "src/components/AuthInput";
import { Input } from "src/components/Input";
import { etrToPem, subsetEt } from "src/util/sign_etr";

export interface SubsetFormInnerProps {
  etPem: Uint8Array;
  et: ExemptionToken;
  privateKeyPem: Uint8Array;
  passphrase: string;
  validityDays: number;
}

export default (props: SubsetFormInnerProps) => {
  const { etPem, et, privateKeyPem, passphrase, validityDays } = props;
  const etr = et.V1.data.request;
  const [contactEmail, setContactEmail] = useState(etr.requestor.email);
  const [contactName, setContactName] = useState(etr.requestor.name);
  const [contactPhone, setContactPhone] = useState(etr.requestor.phone_number);
  const [contactOrcid, setContactOrcid] = useState(etr.requestor.orcid);
  const [exemptionMask, setExemptionMask] = useState(
    etr.exemptions.map((_) => true),
  );
  const [addressMask, setAddressMask] = useState(
    etr.shipping_addresses.map((_) => true),
  );
  const [authenticators, setAuthenticators] = useState<Authenticator[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function downloadSubset() {
    const exemptions = etr.exemptions.filter((_, i) => exemptionMask[i]);
    const addresses = etr.shipping_addresses.filter((_, i) => addressMask[i]);
    setError("");
    setBusy(true);

    setTimeout(() => {
      try {
        const etrPem = etrToPem({
          requestor: {
            name: contactName,
            email: contactEmail,
            phone_number: contactPhone,
            orcid: contactOrcid,
          },
          exemptions,
          shipping_addresses: addresses,
          requestor_auth_devices: authenticators,
          public_key: null,
        });
        const subetPem = subsetEt({
          etPem,
          etrPem,
          privateKeyPem,
          passphrase,
          validityDays,
        });
        const fileName = `${makeFileName(etr.requestor.name || "Anonymous")}-sub.et`;
        download(subetPem, "application/x-pem-file", fileName);
        setError("");
      } catch (e) {
        setError(String(e));
      }
      setBusy(false);
    }, 20);
  }

  return (
    <div className="w-full max-w-3xl flex flex-col">
      <p>
        Uncheck boxes to exclude them from the subset exemption token. Then add
        new two-factor authentication devices for the subset token.
      </p>
      <h2>Exemptions</h2>
      {etr.exemptions.map((exemption, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
        <label className="select-none" key={i}>
          <input
            type="checkbox"
            className="mr-2"
            checked={exemptionMask[i]}
            onChange={(e) =>
              setExemptionMask(
                update(exemptionMask, { [i]: { $set: e.target.checked } }),
              )
            }
          />
          <span>
            <strong>{exemption.name}</strong> (
            {exemption.sequences
              .map((x) => ("Id" in x ? x.Id : "FASTA file"))
              .join(", ")}
            )
          </span>
        </label>
      ))}
      <h2>Shipping Addresses</h2>
      {etr.shipping_addresses.map((address, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
        <label className="select-none" key={i}>
          <input
            type="checkbox"
            className="mr-2"
            checked={addressMask[i]}
            onChange={(e) =>
              setAddressMask(
                update(addressMask, { [i]: { $set: e.target.checked } }),
              )
            }
          />
          <span>{address.join(", ")}</span>
        </label>
      ))}
      <h2>Contact info</h2>
      <div className="mb-4">
        <label htmlFor="contact-email">Email address</label>
        <Input
          type="email"
          id="contact-email"
          value={contactEmail ?? ""}
          onChange={(e) => setContactEmail(e.target.value)}
        />
      </div>
      <div className="mb-4">
        <label htmlFor="contact-name">Name</label>
        <Input
          type="text"
          id="contact-name"
          value={contactName ?? ""}
          onChange={(e) => setContactName(e.target.value)}
        />
      </div>
      <div className="mb-4">
        <label htmlFor="contact-phone">Phone number</label>
        <Input
          type="text"
          id="contact-phone"
          value={contactPhone ?? ""}
          onChange={(e) => setContactPhone(e.target.value)}
        />
      </div>
      <div className="mb-4">
        <label htmlFor="contact-orcid">ORCID iD</label>
        <Input
          type="text"
          id="contact-orcid"
          value={contactOrcid ?? ""}
          placeholder="0000-0000-0000-0000"
          onChange={(e) => setContactOrcid(e.target.value)}
        />
      </div>
      <h2>Two-factor authentication</h2>
      <AuthenticatorsInput
        suggestedValue={etr.requestor_auth_devices}
        suggestedValueLabel="Copy from token"
        value={authenticators}
        setValue={setAuthenticators}
      />
      <h2>Expiry</h2>
      <p>
        The new token will be valid for <strong>{validityDays} days</strong>.
      </p>
      <PrimaryButton
        type="button"
        className="mt-4 mx-auto"
        disabled={
          busy ||
          authenticators.length === 0 ||
          exemptionMask.every((x) => !x) ||
          addressMask.every((x) => !x)
        }
        onClick={downloadSubset}
      >
        {busy ? "Downloading..." : "Download subset token"}
      </PrimaryButton>
      {error && (
        <p className="text-red-500 bg-red-500/10 my-4 py-2 px-4">{error}</p>
      )}
    </div>
  );
};
