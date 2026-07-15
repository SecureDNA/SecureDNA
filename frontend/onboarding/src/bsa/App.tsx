/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faCheck, faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  AddTotp,
  type CertRequestFiles,
  Modal,
} from "@securedna/frontend_common";
import { create_exemption_leaf } from "certificates_wasm";
import { useEffect, useState } from "react";
import { Card } from "../Card";
import { DownloadFile } from "../DownloadFile";

function DownloadFiles(props: { baseName: string; files: CertRequestFiles }) {
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
            />
            — This is a <em>certificate request</em>. You will send this file to
            SecureDNA as detailed below.
          </li>
          <li>
            <DownloadFile
              mimeType="application/x-pem-file"
              contents={props.files.private_key_pem}
              name={`${props.baseName}.priv`}
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
            />
            — This is a <em>public key</em>, which can be freely shared. You do
            not need it for the scenarios described in the quickstart guide, but
            you should preserve it for future use in more-complicated scenarios,
            not described here, in which you might reuse an existing keypair.
          </li>
        </ol>
        <p>
          Once you have downloaded all three files, continue to the registration
          form below. You will be asked to upload the .certr file to that form.
        </p>
        <p>
          If you have already completed the registration form but have not yet
          sent in your .certr file, you can use the{" "}
          <a href="https://securedna.org/cert-upload/">
            certificate upload form
          </a>{" "}
          to submit your .certr file without having to redo the registration
          form.
        </p>
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
  const [showAddTotp, setShowAddTotp] = useState(false);
  const [totpTokenName, setTotpTokenName] = useState("");
  const [showModal, setShowModal] = useState(false);

  const handleGenerate = () => {
    if (!email.includes("@")) {
      setError("Email address should include @");
      return;
    }
    if (passphrase.length < 10) {
      setError("Passphrase should be at least 10 characters long.");
      return;
    }
    setError("");
    setShowModal(true);
  };

  const handleCompleteTotp = (newTotpTokenName: string) => {
    setTotpTokenName(newTotpTokenName);
    setShowModal(false);
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
        files = create_exemption_leaf(
          companyName.trim(),
          email.trim(),
          passphrase.trim(),
          newTotpTokenName.trim(),
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
  };

  // Show the AddTotp component once the user has filled out a company name, email address, and passphrase.
  useEffect(() => {
    if (companyName.trim() && email.trim() && passphrase.trim()) {
      setShowAddTotp(true);
    }
  }, [companyName, email, passphrase]);

  return (
    <>
      <main className="p-4 space-y-4">
        <h2 className="text-2xl">Generating a BSA certificate request</h2>
        <p>
          If you are a biosafety authority, you can use this form to create a{" "}
          <em>BSA certificate request</em>: a request for SecureDNA to grant you
          a BSA certificate. This certificate is used to approve exemption
          requests from researchers.
        </p>
        <p>
          <label htmlFor="company-name-field">Organization name:</label>{" "}
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
        {totpTokenName.trim() === "" ? null : (
          <p>
            <FontAwesomeIcon icon={faCheck} /> Added 2FA token{" "}
            <strong>{totpTokenName}</strong>.
          </p>
        )}
        {showModal && (
          <Modal close={() => setShowModal(false)}>
            <div className="max-w-lg">
              <h2 className="text-xl mb-4">Two-factor authentication</h2>
              <p className="mb-4">
                This token will require two-factor authentication, using an
                authenticator app such as Google Authenticator or Authy.
              </p>
              <AddTotp
                addToken={handleCompleteTotp}
                explanation="When approving an exemption token, you will need to provide the six-digit code from your authenticator app."
              />
            </div>
          </Modal>
        )}
        {error && (
          <p className="text-red">
            <FontAwesomeIcon icon={faWarning} /> {error}
          </p>
        )}

        {files ? (
          <DownloadFiles baseName={baseName} files={files} />
        ) : (
          <button
            className="btn"
            type="button"
            disabled={
              busy || !(companyName.trim() && email.trim() && passphrase.trim())
            }
            onClick={handleGenerate}
          >
            Generate
          </button>
        )}
      </main>
    </>
  );
}

export default App;
