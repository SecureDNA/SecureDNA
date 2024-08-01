/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { download, makeFileName } from "@securedna/frontend_common";
import { useState } from "react";
import {
  AuthCard,
  type AuthFileResult,
  Button,
  OrganismCard,
  PrimaryButton,
} from "src/components";
import { signEtr } from "src/util/sign_etr";
import { useApprovalStore } from "./store";

const SigningPage = () => {
  const [privateKeyPem, setPrivateKeyPem] = useState<AuthFileResult>();

  const [passphrase, setPassphrase] = useState("");
  const [signError, setSignError] = useState("");

  const certPem = useApprovalStore((state) => state.certPem);
  const etr = useApprovalStore((state) => state.etr);
  const etrPem = useApprovalStore((state) => state.etrPem);
  const screenedExemptions = useApprovalStore(
    (state) => state.screenedExemptions,
  );
  const back = useApprovalStore((state) => state.back);

  if (!certPem || !etr || !etrPem || !screenedExemptions) return undefined;

  const has2FA = etr.V1.requestor_auth_devices.length > 0;
  const hasAssociatedKey = etr.V1.public_key !== undefined;
  const validityYears = hasAssociatedKey ? 3 : 1;

  const readyToSign =
    etrPem.ok &&
    certPem.ok &&
    privateKeyPem !== undefined &&
    privateKeyPem.ok &&
    passphrase !== "" &&
    has2FA;

  const sign = () => {
    if (readyToSign) {
      let et: Uint8Array;
      try {
        let flatScreenedExemptions = [...screenedExemptions.values()].flatMap(
          (ans) => [...ans.values()],
        );
        flatScreenedExemptions = [...new Set(flatScreenedExemptions)];
        flatScreenedExemptions.sort();
        et = signEtr({
          etrPem: etrPem.value,
          certPem: certPem.value.array,
          privateKeyPem: privateKeyPem.value.array,
          passphrase,
          validityDays: validityYears * 365,
          screenedExemptions: flatScreenedExemptions,
        });
      } catch (e) {
        console.error(e);
        setSignError(`Signing failed: ${e}.`);
        return;
      }
      const requestorName = etr?.V1?.requestor?.name;
      const fileName = `${makeFileName(requestorName)}.et`;
      setSignError("");
      download(et, "application/x-pem-file", fileName);
    }
  };

  const endDate = new Date(
    new Date().getTime() + 3600 * 24 * 365 * 1000 * validityYears, // unix time of expiry in miliseconds
  ).toLocaleDateString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const requestorName = etr.V1.requestor.name || "Anonymous";

  return (
    <div>
      <h2>Final summary of exemptions</h2>
      <p className="mb-3">
        Exemptions are granted to <strong>{requestorName}</strong> for the
        following organisms, which were listed in their request:
      </p>
      <details className="cursor-pointer mx-4">
        <summary>Expand</summary>
        {etr.V1.exemptions.map((organism, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
          <OrganismCard organism={organism} key={i} compact={false} />
        ))}
      </details>
      {screenedExemptions.size > 0 && (
        <>
          <p className="my-6">
            Additional exemptions are granted for the following organisms and
            accessions, which were found by screening the FASTA sequences in the
            request:
          </p>
          <details className="cursor-pointer mx-4">
            <summary>Expand</summary>
            {[...screenedExemptions].map(([name, ans], i) => {
              const anList = [...ans];
              anList.sort();
              const sequences = anList.map((an) => ({ Id: an }));
              const organism = { name, sequences };
              // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
              return <OrganismCard organism={organism} key={i} />;
            })}
          </details>
        </>
      )}

      <h2>Sign</h2>
      <p className="my-4">
        Authenticate yourself to sign this request. If you don't have a .priv
        file, contact your administrator.
      </p>
      <form>
        <div className="flex space-x-4 mt-4 px-12">
          <AuthCard
            className="flex-1 w-[50%]"
            number={undefined}
            title={"Private key"}
            description={"Prove you're the owner of the certificate."}
            header="-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----"
            acceptExtension={".priv"}
            setPem={setPrivateKeyPem}
            pem={privateKeyPem}
          >
            <input
              className="px-1 border mt-4 w-full"
              type="password"
              placeholder="Passphrase"
              value={passphrase}
              autoComplete="password"
              onChange={(e) => setPassphrase(e.target.value)}
            />
          </AuthCard>
        </div>
        <p className="mt-4 mb-2">
          Signing this request creates an <strong>.et</strong> token file that
          you can send back to the requestor. They can provide this token when
          making a DNA synthesis request.
        </p>
        <p className="my-2">
          The token is valid for
          <strong>
            {` ${validityYears} ${validityYears === 1 ? "year" : "years"}`}
          </strong>
          {` (until ${endDate}).`}
        </p>
        <div className="flex justify-center space-x-2">
          <Button type="button" className="flex-1 my-2 py-3" onClick={back}>
            Back
          </Button>
          <PrimaryButton
            type="button"
            className="flex-[2] my-2 py-3"
            disabled={!readyToSign}
            onClick={sign}
          >
            Sign and download .et
          </PrimaryButton>
        </div>
        {signError && <p className="text-red-500">{signError}</p>}
      </form>
    </div>
  );
};

export default SigningPage;
