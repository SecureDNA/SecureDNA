/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { type HTMLAttributes, type ReactNode, useState } from "react";

import { Setting } from "./Setting";

export interface EtWithPem {
  // token: ExemptionToken;
  pem: string;
}

interface EtInputProps {
  et: EtWithPem | undefined;
  setEt: (et: EtWithPem | undefined) => void;
  yubicoOtp: string;
  setYubicoOtp: (otp: string) => void;
}

export default function EtInput(props: EtInputProps) {
  const [error, setError] = useState("");

  const onUploadEt = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files?.[0]) {
      const reader = new FileReader();
      reader.onload = (loaded) => {
        const result = loaded.target?.result;
        if (result && result instanceof ArrayBuffer) {
          const pem = new Uint8Array(result);
          const pemString = new TextDecoder().decode(pem);
          try {
            // const token = etBundlePemToJsObject(pem);
            props.setEt({ /* token, */ pem: pemString });
            setError("");
          } catch (e) {
            setError(`Could not parse exemption token file: ${e}`);
            props.setEt(undefined);
          }
        } else {
          setError("Could not parse exemption token file.");
          props.setEt(undefined);
        }
      };
      reader.readAsArrayBuffer(event.target.files[0]);
    }
  };

  // This is disabled because having web-interface actually depend on
  // certificates_wasm greatly complicates the build and the benefit is pretty
  // small. Maybe we can use a pure-JavaScript ASN.1 parser if we only need to
  // look inside the exemption token PEM and read some fields.

  // const devices = props.et
  //   ? [
  //       ...props.et.token.V1.data.request.requestor_auth_devices,
  //       ...props.et.token.V1.data.issuer_auth_devices,
  //     ]
  //   : [];

  // const hasYubikey = devices.some((device) => "Yubikey" in device);
  const hasYubikey = true;

  return (
    <>
      <Setting
        label="Token file (.et)"
        input={(props: HTMLAttributes<HTMLElement>): ReactNode => (
          <input type="file" accept=".et" onChange={onUploadEt} />
        )}
      >
        {error}
      </Setting>
      {hasYubikey && (
        <Setting
          label="Touch the Yubikey linked to this token, or enter the six-digit code from your authenticator app:"
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
