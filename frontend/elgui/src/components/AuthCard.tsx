/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  AuthFeedback,
  type AuthFileResult,
  Card,
  FileUpload,
  Input,
} from "@securedna/frontend_common";
import { type ReactNode, useCallback, useState } from "react";
import { useId } from "react";
import type { BundleCheckResult, CertCheckResult } from "../util/checkCert";
import { type CheckSubject, checkCert } from "../util/checkCert";

interface AuthCardProps {
  /**
   * Additional classes for the card.
   */
  className?: string;
  /**
   * A number to show on the upload card.
   */
  number: number | undefined;
  /**
   * The title of the card, naming the auth file it manages.
   */
  title: string;
  /**
   * A noun phrase describing the kind of cert being managed, e.g. "synthesizer token"
   */
  noun: string;
  /**
   * A description of the purpose of the auth file.
   */
  description: string;
  /**
   * A string the uploaded file is expected to start with. e.g.
   * `-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----`
   */
  header: string;
  /**
   * The extension of the file expected to be uploaded, e.g. `.st`
   */
  acceptExtension: string;
  /**
   * Set the current uploaded file.
   */
  setPem?: (pem: AuthFileResult) => void;
  /**
   * The current uploaded file.
   */
  pem: AuthFileResult | undefined;
  /**
   * Set the corresponding private key file.
   */
  setPrivPem?: (pem: AuthFileResult) => void;
  /**
   * The current uploaded private key file.
   */
  privPem?: AuthFileResult | undefined;
  /**
   * A passphrase that decodes the private key file.
   */
  passphrase?: string;
  /**
   * Set the passphrase.
   */
  setPassphrase?: (passphrase: string) => void;
  /**
   * Additional contents to show at the bottom of the card.
   */
  children?: ReactNode;
  /**
   * Callback used to report a validation state after checking the passphrase.
   */
  setValidationState?: (state: "unfilled" | "error" | "ok") => void;
  /**
   * The kind of cert or token to check the contents as.
   */
  checkSubject: CheckSubject;
}

/**
 * A card that invites the user to select a cert or private key and describes
 * what it will be used for.
 */
export const AuthCard = (props: AuthCardProps) => {
  const passphraseId = `passphrase-input-${useId()}`;
  const { passphrase, pem, privPem } = props;
  const [feedback, setFeedback] = useState<
    BundleCheckResult | CertCheckResult | undefined | "loading"
  >();
  const [passphraseNeedsCheck, setPassphraseNeedsCheck] = useState(true);

  const checkPassphrase = useCallback(() => {
    if (!passphraseNeedsCheck) {
      return;
    }
    props.setValidationState?.("unfilled");
    if (passphrase && pem?.ok && privPem?.ok) {
      setFeedback("loading");
      window.setTimeout(() => {
        const result = checkCert(
          pem.value.array,
          privPem.value.array,
          passphrase,
          props.checkSubject,
        );
        setFeedback(result);
        props.setValidationState?.("Ok" in result ? "ok" : "error");
        setPassphraseNeedsCheck(false);
      }, 50);
    }
  }, [
    passphrase,
    pem,
    privPem,
    props.setValidationState,
    props.checkSubject,
    passphraseNeedsCheck,
  ]);
  return (
    <Card
      flavor="primary"
      className={`flex flex-col items-center ${props.className}`}
    >
      <div className="flex justify-center">
        {props.number !== undefined && (
          <span className="w-6 h-6 rounded-full text-center bg-gray-300 font-bold mr-2">
            {props.number}
          </span>
        )}{" "}
        <span className="font-bold">{props.title}</span>
      </div>
      <div className="text-sm my-4 text-center">{props.description}</div>

      <div className="flex gap-2 w-full">
        {props.setPem && (
          <FileUpload
            header={props.header}
            pem={pem}
            setPem={props.setPem}
            label={`Select ${props.noun} (${props.acceptExtension})`}
            noun={props.noun}
            acceptExtension={props.acceptExtension}
          />
        )}
        {props.setPrivPem && (
          <FileUpload
            header="-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----"
            pem={privPem}
            setPem={props.setPrivPem}
            label={"Select private key (.priv)"}
            noun={"private key"}
            acceptExtension=".priv"
          />
        )}
      </div>

      {props.setPassphrase && (
        <div className="w-full flex flex-col">
          <label htmlFor={passphraseId} className="mt-4 text-sm">
            Private key (.priv) passphrase
          </label>
          <Input
            id={passphraseId}
            type="password"
            value={props.passphrase ?? ""}
            onChange={(e) => {
              props.setPassphrase?.(e.target.value);
              setPassphraseNeedsCheck(true);
            }}
            onBlur={checkPassphrase}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                checkPassphrase();
              }
            }}
          />
          {feedback && (
            <div data-testid="auth-feedback">
              <AuthFeedback noun={props.noun} feedback={feedback} />
            </div>
          )}
        </div>
      )}
      {props.children}
    </Card>
  );
};
