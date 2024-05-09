/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { create_manufacturer_leaf } from "certificates_wasm";
import { useState } from "react";
import { CertRequestFiles } from "@securedna/frontend_common";

function DownloadPem(props: { contents: string; name: string }) {
  return (
    <a
      href={
        "data:application/x-pem-file;charset=utf-8," +
        encodeURIComponent(props.contents)
      }
      download={props.name}
    >
      {props.name}
    </a>
  );
}

function DownloadFiles(props: { baseName: string; files: CertRequestFiles }) {
  return (
    <>
      <div className="bg-primary space-y-4 py-4 px-6 rounded">
        <h3 className="text-xl">Download your files</h3>
        <ol className="space-y-4 list-decimal ml-6">
          <li>
            <DownloadPem
              contents={props.files.certr_pem}
              name={props.baseName + ".certr"}
            />
            : This is a <em>certificate request</em>. You will send this file to
            SecureDNA as detailed below.
          </li>
          <li>
            <a
              href={
                "data:application/x-pem-file;charset=utf-8," +
                encodeURIComponent(props.files.private_key_pem)
              }
              download={props.baseName + ".priv"}
            >
              {props.baseName + ".priv"}
            </a>
            : This is a <em>private key</em>, protected by your passphrase. Do{" "}
            <strong>not</strong> send this to SecureDNA, do not lose it, and do
            not share it. (If you send it to SecureDNA by mistake, we will ask
            you to generate a new certificate request and to throw away the
            existing request.)
          </li>
          <li>
            <a
              href={
                "data:application/x-pem-file;charset=utf-8," +
                encodeURIComponent(props.files.public_key_pem)
              }
              download={props.baseName + ".pub"}
            >
              {props.baseName + ".pub"}
            </a>
            : This is a <em>public key</em>, which can be freely shared. You do
            not need it for the scenarios described in the quickstart guide, but
            you should preserve it for future use in more-complicated scenarios,
            not described here, in which you might reuse an existing keypair.
          </li>
        </ol>
        <p>
          Once you have downloaded all three files, continue to the{" "}
          <a className="font-bold" href="https://securedna.org/start/">
            Screening Registration Form
          </a>{" "}
          and upload the <code>.certr</code> file there.
        </p>
      </div>
    </>
  );
}

function App() {
  const [companyName, setCompanyName] = useState("");
  const [email, setEmail] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [baseName, setBaseName] = useState("");
  const [busy, setBusy] = useState(false);
  const [files, setFiles] = useState<CertRequestFiles>();

  return (
    <>
      <header className="bg-primary p-4">
        <h1 className="text-4xl text-center">SecureDNA onboarding</h1>
      </header>
      <main className="p-4 space-y-4 max-w-prose mx-auto">
        <h2 className="text-2xl">Generating a certificate request</h2>
        <p>
          synthclient is free to use, but requires a certificate for
          authentication to the screening servers to prevent various types of
          abuse.
        </p>
        <p>
          This form lets you create a <em>certificate request</em>, which is a
          request for SecureDNA to grant you a manufacturer certificate. Your
          browser will generate three files for you to download.
        </p>
        <p>
          <label htmlFor="company-name-field">Company name:</label>{" "}
          <input
            id="company-name-field"
            className="input"
            type="text"
            value={companyName}
            onChange={(e) => setCompanyName(e.target.value)}
          ></input>
        </p>
        <p>
          <label htmlFor="email-field">Email:</label>{" "}
          <input
            id="email-field"
            className="input"
            type="text"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="some-email@companyname.com"
          ></input>
        </p>
        <p>
          <label htmlFor="passphrase-field">Passphrase:</label>{" "}
          <input
            id="passphrase-field"
            className="input"
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          ></input>
        </p>
        <button
          className="btn"
          type="button"
          disabled={
            busy ||
            !(companyName.trim() && email.includes("@") && passphrase.trim())
          }
          onClick={() => {
            setBaseName(
              (companyName || "anonymous")
                .replaceAll(/\W+/gu, "-")
                .replaceAll(/-+/gu, "-")
                .replaceAll(/^-|-$/gu, "")
                .toLowerCase() + "-leaf"
            );
            setBusy(true);
            setTimeout(() => {
              setFiles(
                create_manufacturer_leaf(
                  companyName.trim(),
                  email.trim(),
                  passphrase.trim()
                )
              );
              setTimeout(() => {
                window.scrollTo(0, document.body.scrollHeight);
                setBusy(false);
              }, 0);
            }, 50);
          }}
        >
          Generate
        </button>
        {files ? (
          <DownloadFiles baseName={baseName} files={files} />
        ) : undefined}
      </main>
    </>
  );
}

export default App;
