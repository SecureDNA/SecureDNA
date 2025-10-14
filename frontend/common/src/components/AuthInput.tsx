/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import _ from "lodash";
import { useState } from "react";
import type { Authenticator } from "../all_bindings";
import { authenticatorCode, authenticatorName } from "../util/authenticator";
import { AddTotp } from "./AddTotp";
import { Button } from "./Button";
import { Input } from "./Input";
import { LinkButton } from "./LinkButton";
import { Modal } from "./Modal";
import { PrimaryButton } from "./PrimaryButton";

const YUBIKEY_ID_LENGTH = 12;

export function parseYubikeyId(yubikeyId: string): Authenticator {
  const candidate = [...yubikeyId.toUpperCase()];
  if (yubikeyId.length !== YUBIKEY_ID_LENGTH) {
    throw new Error(
      `Invalid Yubikey ID length: ${yubikeyId.length} (should be ${YUBIKEY_ID_LENGTH})`,
    );
  }

  for (const letter of candidate) {
    if ("CBDEFGHIJKLNRTUV".indexOf(letter) === -1) {
      throw new Error(`Invalid modhex character: ${letter}`);
    }
  }
  return { Yubikey: yubikeyId.toLowerCase() };
}

interface AuthenticatorsInputProps {
  value: Authenticator[];
  setValue: (value: Authenticator[]) => void;
  onBlur?: (e: React.FocusEvent<HTMLInputElement>) => void;
  suggestedValue?: Authenticator[];
  suggestedValueLabel?: string;
}

export const ListedAuthenticator = (props: {
  authenticator: Authenticator;
  remove: () => void;
}) => {
  return (
    <li className="">
      <span className="">
        {authenticatorName(props.authenticator)}:{" "}
        <strong>{authenticatorCode(props.authenticator)}</strong>
      </span>{" "}
      (
      <LinkButton type="button" onClick={props.remove}>
        remove
      </LinkButton>
      )
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
            "Yubikey" in authenticator && authenticator.Yubikey === idPart,
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
          "Totp" in authenticator && authenticator.Totp === token,
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

  const addSuggested = _.union(props.value, props.suggestedValue!);

  return (
    <div className="flex flex-col">
      <ol className="px-4 py-2 flex flex-col gap-2">
        {value.map((auth, i) => (
          <ListedAuthenticator
            key={JSON.stringify(auth)}
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
        {props.suggestedValue ? (
          <>
            <PrimaryButton
              type="button"
              onClick={() => props.setValue(addSuggested)}
              disabled={_.isEqual(props.value, addSuggested)}
            >
              {props.suggestedValueLabel}
            </PrimaryButton>
          </>
        ) : (
          <Button type="button" onClick={() => setModal("totp")}>
            Add TOTP (Authenticator app)
          </Button>
        )}
        <Button type="button" onClick={() => setModal("yubikey")}>
          Add Yubikey (physical key)
        </Button>
      </div>
      {modal && (
        <Modal
          close={() => {
            setError("");
            setModal(undefined);
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
                <Input
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
              <div className="max-w-lg">
                <AddTotp addToken={addTotpToken} />
              </div>
            </>
          )}
        </Modal>
      )}
    </div>
  );
};
