/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { useCallback, useEffect, useState } from "react";
import { PrimaryButton } from "./PrimaryButton";
import { Spinner } from "./Spinner";

interface AddTotpProps {
  addToken: (name: string) => void;
}

export const AddTotp = (props: AddTotpProps) => {
  const [imageUrl, setImageUrl] = useState<string>();
  const [otp, setOtp] = useState("");
  const [tokenName, setTokenName] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>("");
  const [started, setStarted] = useState(false);
  useEffect(() => {
    if (started) return;
    setStarted(true);
    setErrorMessage("");
    setBusy(true);
    fetch("https://pi.securedna.org/securedna/token/v1/token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ time: Date.now() / 1000 }),
    })
      .then(async (response) => {
        const body = (await response.json()) as any;
        setImageUrl(body.detail.googleurl.img);
        setTokenName(body.detail.serial);
        setBusy(false);
      })
      .catch(async (e) => {
        setImageUrl("");
        setTokenName("");
        setBusy(false);
        setErrorMessage("Couldn't connect to token server. Try again later.");
      });
  }, [started]);
  const checkOtp = useCallback(() => {
    if (!/^\d{6}$/.test(otp)) {
      setErrorMessage("Code must be 6 digits");
      return;
    }
    setErrorMessage("");
    setBusy(true);
    fetch("https://pi.securedna.org/securedna/token/v1/check", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        time: Date.now() / 1000,
        serial: tokenName,
        pass: otp,
      }),
    }).then(async (response) => {
      const body = (await response.json()) as any;
      setOtp("");
      setBusy(false);

      if (tokenName && body.result.value) {
        props.addToken(tokenName);
      } else {
        setErrorMessage(`Error: ${body?.detail?.message ?? "unknown error"}`);
      }
    });
  }, [otp, tokenName, props.addToken]);
  useEffect(() => {
    if (otp.length === 6) checkOtp();
  }, [otp, checkOtp]);

  return (
    <div className="max-w-lg">
      <p>Scan the QR code below to add it your authenticator app:</p>
      <div className="flex justify-center my-4">
        {imageUrl ? (
          <img style={{ height: "225px" }} src={imageUrl} alt="QR code" />
        ) : (
          <div
            className="text-center flex items-center justify-center select-none bg-black/5"
            style={{ height: "225px", width: "225px" }}
          >
            {busy && <Spinner />}
          </div>
        )}
      </div>
      <p className="my-2">
        Its name is{" "}
        <strong>
          SecureDNA (
          {tokenName || (
            <span className="bg-black/5 inline-block px-16">&nbsp;</span>
          )}
          )
        </strong>
        . This name will be tied to your exemption token. When submitting a
        synthesis order, you will need to provide the six-digit code from your
        authenticator app.
      </p>
      <p>Enter the six-digit code to confirm:</p>
      <div className="flex mt-4 gap-2">
        <input
          disabled={busy}
          className="border rounded flex-1 leading-none p-2 outline-blue-500"
          value={otp}
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={6}
          onChange={(e) => {
            setOtp(e.target.value.trim());
          }}
          name="otp"
          placeholder={"Six-digit code"}
        />
        <PrimaryButton disabled={busy} type="button" onClick={() => checkOtp()}>
          Check
        </PrimaryButton>
      </div>
      <p className="mt-4 text-red-500">{errorMessage}</p>
    </div>
  );
};
