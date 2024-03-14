/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { HTMLAttributes, ReactNode, useState } from "react";

import { Setting } from "./Setting";

export interface EltWithPem {
  // token: ExemptionListToken;
  pem: string;
}

interface EltInputProps {
  elt: EltWithPem | undefined;
  setElt: (elt: EltWithPem | undefined) => void;
  yubicoOtp: string;
  setYubicoOtp: (otp: string) => void;
}

export default function EltInput(props: EltInputProps) {
  const [error, setError] = useState("");

  const onUploadElt = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      const reader = new FileReader();
      reader.onload = (loaded) => {
        const result = loaded.target?.result;
        if (result && result instanceof ArrayBuffer) {
          const pem = new Uint8Array(result);
          const pemString = new TextDecoder().decode(pem);
          try {
            // const token = eltBundlePemToJsObject(pem);
            props.setElt({ /* token, */ pem: pemString });
            setError("");
          } catch (e) {
            setError("Could not parse ELT file: " + e);
            props.setElt(undefined);
          }
        } else {
          setError("Could not parse ELT file.");
          props.setElt(undefined);
        }
      };
      reader.readAsArrayBuffer(event.target.files[0]);
    }
  };

  // This is disabled because having demo_gui actually depend on
  // certificates_wasm greatly complicates the build and the benefit is pretty
  // small. Maybe we can use a pure-JavaScript ASN.1 parser if we only need to
  // look inside the ELT PEM and read some fields.

  // const devices = props.elt
  //   ? [
  //       ...props.elt.token.V1.data.request.requestor_auth_devices,
  //       ...props.elt.token.V1.data.issuer_auth_devices,
  //     ]
  //   : [];

  // const hasYubikey = devices.some((device) => "Yubikey" in device);
  const hasYubikey = true;

  return (
    <>
      <Setting
        label="Exemption List Token"
        input={function (props: HTMLAttributes<HTMLElement>): ReactNode {
          return <input type="file" accept=".elt" onChange={onUploadElt} />;
        }}
      >
        {error}
      </Setting>
      {hasYubikey && (
        <Setting
          label="Touch your Yubikey to generate a one-time passcode:"
          input={(inputProps) => (
            <input
              maxLength={44}
              className={inputProps.className}
              type="text"
              onChange={(e) => props.setYubicoOtp(e.target.value)}
              value={props.yubicoOtp}
            />
          )}
        />
      )}
    </>
  );
}
