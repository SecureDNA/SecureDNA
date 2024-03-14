/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { Authenticator } from "@securedna/frontend_common";
import { useState } from "react";
import { RemoveButton } from "./RemoveButton";
import { Button } from "./Button";
import { parseYubikeyId } from "src/util/sign_eltr";

interface AuthenticatorsInputProps {
  value: Authenticator[];
  setValue: (value: Authenticator[]) => void;
  onBlur?: (e: React.FocusEvent<HTMLInputElement>) => void;
}

export const ListedAuthenticator = (props: {
  authenticator: Authenticator;
  remove: () => void;
}) => {
  if ("Yubikey" in props.authenticator) {
    return (
      <li className="px-4 py-2 flex">
        <span className="flex-1">
          Yubikey:{" "}
          <strong>{props.authenticator.Yubikey.join("").toLowerCase()}</strong>
        </span>
        <RemoveButton className="w-6" onClick={props.remove} />
      </li>
    );
  }
};

export const AuthenticatorsInput = (props: AuthenticatorsInputProps) => {
  const { value, setValue } = props;
  const [otp, setOtp] = useState("");
  const [error, setError] = useState<string>();

  const addYubikey = (e: React.MouseEvent<HTMLButtonElement, MouseEvent>) => {
    try {
      const idPart = otp.trim().toLowerCase().slice(0, 12);
      const id = parseYubikeyId(idPart);
      if (value.some((v) => v.Yubikey.join("").toLowerCase() === idPart)) {
        setError("This Yubikey was already added.");
        return;
      }
      setValue([...value, id]);
      setOtp("");
      setError("");
    } catch (e) {
      setError(String(e));
      return;
    }
  };

  return (
    <div className="flex flex-col">
      <ol className="list-inside list-decimal">
        {value.map((auth, i) => (
          <ListedAuthenticator
            key={i}
            authenticator={auth}
            remove={() => {
              setValue([...value.slice(0, i), ...value.slice(i + 1)]);
            }}
          />
        ))}
      </ol>
      {value.length === 0 && (
        <p className="px-4 py-2 italic">No authenticator devices added.</p>
      )}
      <div className="flex flex-row gap-2">
        <input
          className="border rounded flex-1 leading-none p-2 outline-blue-500"
          value={otp}
          onChange={(e) => setOtp(e.target.value)}
          name="otp"
          onBlur={(e) => props.onBlur?.(e)}
          placeholder={"Yubikey OTP"}
        />
        <Button type="button" onClick={addYubikey}>
          Add Yubikey
        </Button>
      </div>
      <div className="text-red-600">{error}</div>
    </div>
  );
};
