/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { download } from "@securedna/frontend_common";
import { useState } from "react";
import { makeKeypair } from "src/util/sign_etr";
import { PrimaryButton } from "./PrimaryButton";

export interface MakeKeypairProps {
  setPublicKey: (hexpem: string) => void;
  privateKeyFileName: string;
  close: () => void;
}

export const MakeKeypair = (props: MakeKeypairProps) => {
  const [passphrase, setPassphrase] = useState("");

  return (
    <div className="max-w-lg">
      <h2>New keypair</h2>
      <p className="my-2">Enter a passphrase below to create a new keypair.</p>
      <ul className="ml-8 list-disc">
        <li>
          The <strong>public key</strong> will be embedded in the exemption
          token request.
        </li>
        <li>
          The <strong>private key</strong> will be downloaded to your device.
        </li>
      </ul>
      <p className="my-2">
        Save the private key, and don't send it to anyone: you can later use it
        to create sub exemption tokens.
      </p>
      <div className="flex">
        <input
          type="password"
          className="border rounded flex-1 leading-none p-2 my-2 outline-blue-500"
          onChange={(e) => {
            setPassphrase(e.target.value.trim());
          }}
          name="passphrase"
          placeholder={"Passphrase (at least 10 characters)"}
        />
        <PrimaryButton
          disabled={passphrase.length < 10}
          className="m-2"
          type="button"
          onClick={() => {
            const keypair = makeKeypair(passphrase);
            download(
              keypair.private_key_pem,
              "application/x-pem-file",
              `${props.privateKeyFileName}-${keypair.public_key_hexpem.substring(0, 12)}.priv`,
            );
            props.setPublicKey(keypair.public_key_hexpem);
            props.close();
          }}
        >
          Generate
        </PrimaryButton>
      </div>
    </div>
  );
};
