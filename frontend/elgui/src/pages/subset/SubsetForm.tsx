/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { type AuthFileResult, Page } from "@securedna/frontend_common";
import { useMemo, useState } from "react";
import { AuthCard } from "src/components/AuthCard";
import { CheckSubject } from "src/util/checkCert";
import { etBundlePemToJsObject } from "src/util/sign_etr";
import SubsetFormInner from "./SubsetFormInner";

const validityDays = 90;

export default () => {
  const [etPem, setEtPem] = useState<AuthFileResult>();
  const [privateKeyPem, setPrivateKeyPem] = useState<AuthFileResult>();

  const [passphrase, setPassphrase] = useState("");
  const et = useMemo(() => {
    if (!etPem?.ok) return undefined;
    const result = etBundlePemToJsObject(etPem.value.array);
    if (!result.ok) return undefined;
    return result.value;
  }, [etPem]);

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
            noun={"exemption token"}
            description={"Select an exemption token to subset."}
            header="-----BEGIN SECUREDNA EXEMPTION TOKEN-----"
            acceptExtension={".et"}
            setPem={setEtPem!}
            pem={etPem!}
            setPrivPem={setPrivateKeyPem}
            privPem={privateKeyPem}
            passphrase={passphrase}
            setPassphrase={setPassphrase}
            checkSubject={CheckSubject.ExemptionToken}
          />
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
