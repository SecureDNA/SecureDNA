/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { Authenticator } from "@securedna/frontend_common";
import { useState } from "react";
import { RemoveButton } from "./RemoveButton";
import { Button } from "./Button";
import { parseYubikeyId } from "src/util/sign_eltr";
import { AddTotp } from "./AddTotp";
import { authenticatorCode, authenticatorName } from "src/util/authenticator";

interface AuthenticatorsInputProps {
  value: Authenticator[];
  setValue: (value: Authenticator[]) => void;
  onBlur?: (e: React.FocusEvent<HTMLInputElement>) => void;
}

export const ListedAuthenticator = (props: {
  authenticator: Authenticator;
  remove: () => void;
}) => {
  return (
    <li className="px-4 py-2 flex bg-black/5 rounded">
      <span className="flex-1">
        {authenticatorName(props.authenticator)}:{" "}
        <strong>{authenticatorCode(props.authenticator)}</strong>
      </span>
      <RemoveButton className="w-6" onClick={props.remove} />
    </li>
  );
};

export const AuthenticatorsInput = (props: AuthenticatorsInputProps) => {
  const { value, setValue } = props;
  const [modal, setModal] = useState<"yubikey" | "totp">();
  const [otp, setOtp] = useState("");
  const [error, setError] = useState<string>();

  const addYubikey = (e: React.MouseEvent<HTMLButtonElement, MouseEvent>) => {
    try {
      const idPart = otp.trim().toLowerCase().slice(0, 12);
      const id = parseYubikeyId(idPart);
      if (
        value.some(
          (authenticator) =>
            "Yubikey" in authenticator &&
            authenticator.Yubikey.join("").toLowerCase() === idPart
        )
      ) {
        setError("This Yubikey was already added.");
        return;
      }
      setValue([...value, id]);
      setOtp("");
      setError("");
      setModal(undefined);
    } catch (err) {
      setError(String(err));
      return;
    }
  };

  const addTotpToken = (token: string) => {
    if (
      value.some(
        (authenticator) =>
          "Totp" in authenticator && authenticator.Totp === token
      )
    ) {
      setError("This TOTP key was already added.");
      return;
    }
    setValue([...value, { Totp: token }]);
    setOtp("");
    setError("");
    setModal(undefined);
  };

  return (
    <div className="flex flex-col">
      <ol className="flex flex-col gap-2">
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
      <div className="flex flex-row gap-2 mt-2">
        <Button type="button" onClick={() => setModal("yubikey")}>
          Add Yubikey (physical key)
        </Button>
        <Button type="button" onClick={() => setModal("totp")}>
          Add TOTP (Authenticator app)
        </Button>
      </div>
      {modal && (
        <div
          className="fixed inset-0 transition-opacity bg-black/50 z-20 flex"
          onClick={() => {
            setError("");
            setModal(undefined);
          }}
        >
          <div
            className="relative max-h-screen overflow-y-auto px-6 py-4 rounded-xl shadow-xl mx-auto z-30 bg-white my-auto"
            onClick={(e) => {
              e.stopPropagation();
            }}
          >
            {modal === "yubikey" ? (
              <>
                <h2>Adding a Yubikey</h2>
                <p className="my-2">
                  Click the field below, then touch your Yubikey to generate an
                  OTP.
                </p>
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
                <div className="mt-2 text-red-600">{error}</div>
              </>
            ) : (
              <>
                <h2>Adding TOTP-based 2FA</h2>
                <AddTotp addToken={addTotpToken} />
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
