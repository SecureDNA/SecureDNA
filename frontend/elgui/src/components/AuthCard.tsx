/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faCancel, faCheck } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Result } from "@securedna/frontend_common";
import { ReactNode, useRef } from "react";
import { PrimaryButton } from "./PrimaryButton";

export type AuthFileResult = Result<
  { array: Uint8Array; name: string },
  string
>;

/**
 * An onChange handler for file uploads that calls a bound setter with the
 * contents of the uploaded file.
 */
function loadFromFile(
  header: string,
  setter: (result: AuthFileResult) => void,
  e: React.ChangeEvent<HTMLInputElement>
): void {
  const files = e.currentTarget.files;
  if (!files || files.length === 0) {
    setter({ ok: false, error: "No file was selected." });
    return;
  }
  if (files.length > 1) {
    setter({ ok: false, error: "Multiple file upload is not allowed." });
    return;
  }
  const file = files[0];
  const name = file.name;
  const reader = new FileReader();
  reader.onerror = () => {
    setter({ ok: false, error: `File ${file.name} could not be read.` });
  };
  reader.onload = (loaded) => {
    const array = new Uint8Array(loaded.target?.result as ArrayBuffer);
    const headerView = array.slice(0, header.length);
    const headerText = new TextDecoder().decode(headerView) ?? "";
    if (!headerText.startsWith(header)) {
      setter({
        ok: false,
        error: `File ${file.name} is not a valid certificate.`,
      });
      return;
    }
    setter({ ok: true, value: { array, name } });
  };
  reader.readAsArrayBuffer(file);
}

interface AuthCardProps {
  className?: string;
  number: number | undefined;
  title: string;
  description: string;
  header: string;
  acceptExtension: string;
  setPem: (array: AuthFileResult) => void;
  pem: AuthFileResult | undefined;
  children?: ReactNode;
}

/**
 * A card that invites the user to upload a cert or private key and describes
 * what it will be used for.
 */
export const AuthCard = (props: AuthCardProps) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const pem = props.pem;
  return (
    <div
      className={
        "flex flex-col items-center bg-gray-200 px-6 py-5 " + props.className
      }
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
      <PrimaryButton
        type="button"
        className="w-full"
        onClick={() => inputRef.current?.click()}
      >
        Select {props.acceptExtension}
      </PrimaryButton>
      <input
        ref={inputRef}
        hidden
        type="file"
        accept={props.acceptExtension}
        onChange={loadFromFile.bind(this, props.header, props.setPem)}
      />
      <div className="mt-2 select-none w-full">
        {pem?.ok === false ? (
          <p className="text-red-500 overflow-hidden text-ellipsis text-sm">
            <FontAwesomeIcon icon={faCancel} className="mr-2" />
            {pem.error}
          </p>
        ) : pem?.ok === true ? (
          <p className="text-green-500 overflow-hidden text-ellipsis text-sm">
            <FontAwesomeIcon icon={faCheck} className="mr-2" />
            Selected {pem.value.name}
          </p>
        ) : (
          <p className="opacity-50 overflow-hidden text-ellipsis text-sm">
            No file selected
          </p>
        )}
      </div>
      {props.children}
    </div>
  );
};
