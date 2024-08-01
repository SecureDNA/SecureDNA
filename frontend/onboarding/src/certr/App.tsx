/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import type { CertRequestFiles } from "@securedna/frontend_common";
import { create_manufacturer_leaf } from "certificates_wasm";
import { useState } from "react";
import { Card } from "../Card";
import { DownloadFile } from "../DownloadFile";

function DownloadFiles(props: { baseName: string; files: CertRequestFiles }) {
  const [gotCertr, setGotCertr] = useState(false);
  const [gotPriv, setGotPriv] = useState(false);
  const [gotPub, setGotPub] = useState(false);
  const gotAll = gotCertr && gotPriv && gotPub;

  return (
    <>
      <Card>
        <h3 className="text-xl">Download your files</h3>
        <ol className="space-y-4 list-decimal ml-6">
          <li>
            <DownloadFile
              mimeType="application/x-pem-file"
              contents={props.files.certr_pem}
              name={`${props.baseName}.certr`}
              onClick={() => setGotCertr(true)}
            />
            — This is a <em>certificate request</em>. You will send this file to
            SecureDNA as detailed below.
          </li>
          <li>
            <DownloadFile
              mimeType="application/x-pem-file"
              contents={props.files.private_key_pem}
              name={`${props.baseName}.priv`}
              onClick={() => setGotPriv(true)}
            />
            — This is a <em>private key</em>, protected by your passphrase. Do{" "}
            <strong>not</strong> send this to SecureDNA, do not lose it, and do
            not share it. (If you send it to SecureDNA by mistake, we will ask
            you to generate a new certificate request and to throw away the
            existing request.)
          </li>
          <li>
            <DownloadFile
              mimeType="application/x-pem-file"
              contents={props.files.public_key_pem}
              name={`${props.baseName}.pub`}
              onClick={() => setGotPub(true)}
            />
            — This is a <em>public key</em>, which can be freely shared. You do
            not need it for the scenarios described in the quickstart guide, but
            you should preserve it for future use in more-complicated scenarios,
            not described here, in which you might reuse an existing keypair.
          </li>
        </ol>
        <p>
          Once you have downloaded all three files, continue to the Screening
          Registration Form and upload the <code>.certr</code> file there.
        </p>
        <a
          className={
            gotAll
              ? "btn !no-underline"
              : "btn !no-underline opacity-50 cursor-default"
          }
          href={gotAll ? "https://securedna.org/start/" : undefined}
        >
          Continue
        </a>
      </Card>
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
  const [error, setError] = useState("");

  return (
    <>
      <main className="p-4 space-y-4">
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
          />
        </p>
        <p>
          <label htmlFor="email-field">Email address:</label>{" "}
          <input
            id="email-field"
            className="input"
            type="text"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="some-email@companyname.com"
          />
        </p>
        <p>
          <label htmlFor="passphrase-field">Passphrase:</label>{" "}
          <input
            id="passphrase-field"
            className="input"
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
        </p>
        {error && (
          <p className="text-red">
            <FontAwesomeIcon icon={faWarning} /> {error}
          </p>
        )}
        <button
          className="btn"
          type="button"
          disabled={
            busy || !(companyName.trim() && email.trim() && passphrase.trim())
          }
          onClick={() => {
            if (!email.includes("@")) {
              setError("Email address should include @");
              return;
            }
            if (passphrase.length < 10) {
              setError("Passphrase should be at least 10 characters long.");
              return;
            }
            setError("");
            setBaseName(
              `${(companyName || "anonymous")
                .replaceAll(/\W+/gu, "-")
                .replaceAll(/-+/gu, "-")
                .replaceAll(/^-|-$/gu, "")
                .toLowerCase()}-leaf`,
            );
            setBusy(true);
            setTimeout(() => {
              let files: CertRequestFiles;
              try {
                files = create_manufacturer_leaf(
                  companyName.trim(),
                  email.trim(),
                  passphrase.trim(),
                );
              } catch (e) {
                setError(String(e));
                setBusy(false);
                return;
              }

              setFiles(files);
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
