/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { useMemo, useState } from "react";
import { AuthCard, type AuthFileResult, Page } from "src/components";
import { etBundlePemToJsObject } from "src/util/sign_etr";
import SubsetFormInner from "./SubsetFormInner";

const validityDays = 90;

export default () => {
  const [etPem, setEtPem] = useState<AuthFileResult>();
  const [privateKeyPem, setPrivateKeyPem] = useState<AuthFileResult>();

  const [passphrase, setPassphrase] = useState("");
  const et = useMemo(
    () => (etPem?.ok ? etBundlePemToJsObject(etPem.value.array) : undefined),
    [etPem],
  );

  return (
    <Page title="Subsetting Tool">
      <div className="w-full max-w-3xl my-4">
        <p>
          This tool allows researchers to create a "subset" of an exemption
          token, which may cover only a subset of the exempt organisms, or have
          different 2FA devices.
        </p>
        <p className="my-4">
          The exemption token must have been created with a public key. Select
          the corresponding private key to make a subset.
        </p>
        <div className="flex gap-2 my-4">
          <AuthCard
            className="flex-1"
            number={undefined}
            title={"Exemption token"}
            description={"Select an exemption token to subset."}
            header="-----BEGIN SECUREDNA EXEMPTION TOKEN-----"
            acceptExtension={".et"}
            setPem={setEtPem!}
            pem={etPem!}
          />

          <AuthCard
            className="flex-1"
            number={undefined}
            title={"Private key"}
            description={"Prove you're the owner of the exemption token."}
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
      </div>
      {privateKeyPem?.ok &&
        etPem?.ok &&
        et &&
        (et.V1.data.request.public_key ? (
          <SubsetFormInner
            etPem={etPem.value.array}
            et={et}
            key={et.V1.signature.toString()}
            privateKeyPem={privateKeyPem.value.array}
            passphrase={passphrase}
            validityDays={validityDays}
          />
        ) : (
          <p className="text-red-500">
            This exemption token was created without a public key and cannot be
            subsetted.
          </p>
        ))}
      <div className="h-8" />
    </Page>
  );
};
