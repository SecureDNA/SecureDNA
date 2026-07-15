/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import * as fa from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  AuthFeedback,
  type CertCheckResult,
  type SynthesizerTokenFiles,
} from "@securedna/frontend_common";
import { check_manufacturer_cert } from "certificates_wasm";
import { useCallback, useState } from "react";
import { useForm } from "react-hook-form";
import { Card } from "../Card";
import { ConfigureToken } from "./ConfigureToken";
import { DownloadFiles } from "./DownloadFiles";
import { SelectPurpose } from "./SelectPurpose";
import { UploadPem } from "./UploadPem";
import {
  type AuditKeySource,
  type FormValues,
  defaultPurpose,
  submitSynthTokenForm,
} from "./submit";

enum CertStatus {
  Empty = 0,
  Pending = 1,
  Ok = 2,
  Error = 3,
}

function App() {
  const { register, setValue, watch, handleSubmit, formState } =
    useForm<FormValues>({
      defaultValues: { purpose: defaultPurpose() },
    });
  const [busy, setBusy] = useState(false);
  const [files, setFiles] = useState<SynthesizerTokenFiles>();

  const [certPem, setCertPem] = useState("");
  const [privPem, setPrivPem] = useState("");
  const [certStatus, setCertStatus] = useState(CertStatus.Empty);
  const [certSummary, setCertSummary] = useState<CertCheckResult | "loading">();
  const [auditKeySource, setAuditKeySource] = useState<AuditKeySource>("new");

  const [error, setError] = useState("");
  const watchPurpose = watch("purpose", defaultPurpose());

  const onSubmit = useCallback(
    (data: FormValues) =>
      submitSynthTokenForm(
        data,
        certPem,
        privPem,
        auditKeySource,
        setError,
        setBusy,
        setFiles,
      ),
    [privPem, certPem, auditKeySource],
  );

  return (
    <form className="p-4 space-y-4" onSubmit={handleSubmit(onSubmit)}>
      <h2 className="text-2xl">Creating a synthesizer token</h2>
      <p>
        This form lets you create <em>synthesizer tokens</em> from a SecureDNA
        certificate. How many you make depends on how your business is
        structured.
      </p>
      <ol className="space-y-4 list-disc ml-6">
        <li>
          If you are a <strong>centralized provider</strong>, you can make a
          single token for all of your screening, and supply that token with
          every request.
        </li>
        <li>
          If you are a <strong>benchtop manufacturer</strong>, you should make
          one token per printer.
        </li>
        <li>
          If you are a <strong>biosafety authority</strong> in charge of
          approving synthesis exemptions, you should make a single token, and
          use that token in your approvals.
        </li>
      </ol>
      <p>
        First, upload your manufacturer certificate and enter its passphrase.
        Your private key will <strong>not</strong> be uploaded to SecureDNA. The
        token creation happens in your browser.
      </p>
      <Card>
        <h3 className="text-xl">Manufacturer certificate</h3>
        <div className="flex flex-col md:flex-row gap-4">
          <UploadPem
            title="Certificate"
            header="-----BEGIN SECUREDNA MANUFACTURER CERTIFICATE-----"
            accept=".cert"
            onUpload={(pem) => {
              setCertStatus(CertStatus.Empty);
              setCertSummary(undefined);
              setCertPem(pem);
            }}
          />
          <UploadPem
            title="Private key"
            header="-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----"
            accept=".priv"
            onUpload={(pem) => {
              setCertStatus(CertStatus.Empty);
              setCertSummary(undefined);
              setPrivPem(pem);
            }}
          />
        </div>
        <p>
          <label htmlFor="mf-passphrase">
            Manufacturer certificate passphrase:
          </label>{" "}
          <input
            {...register("certPassphrase", { required: true })}
            className="input"
            type="password"
            id="mf-passphrase"
            onBlur={(e) => {
              setCertStatus(CertStatus.Pending);
              setCertSummary("loading");
              setTimeout(() => {
                const summary: CertCheckResult = check_manufacturer_cert(
                  certPem,
                  privPem,
                  e.target.value,
                );

                if ("Ok" in summary) {
                  setCertStatus(CertStatus.Ok);
                  setCertSummary(summary);
                } else {
                  setCertStatus(CertStatus.Error);
                  setCertSummary(summary);
                }
              }, 1);
            }}
          />
        </p>
        {certStatus !== CertStatus.Empty && certSummary && (
          <AuthFeedback noun="certificate" feedback={certSummary} />
        )}
      </Card>
      <SelectPurpose register={register} name="purpose" />
      <p>
        Then, configure the{" "}
        {watchPurpose === "screening" ? "screening" : "synthesizer"} token
        below.
      </p>

      <ConfigureToken
        register={register}
        setValue={setValue}
        watch={watch}
        purpose={watchPurpose}
        auditKeySource={auditKeySource}
        setAuditKeySource={setAuditKeySource}
      />
      {error && (
        <p className="text-error">
          <FontAwesomeIcon icon={fa.faWarning} /> {error}
        </p>
      )}
      <button
        className="btn"
        type="submit"
        disabled={busy || !formState.isValid}
      >
        Generate
      </button>
      {files ? (
        <DownloadFiles
          screening={watchPurpose === "screening"}
          baseName={"token"}
          files={files}
        />
      ) : undefined}
    </form>
  );
}

export default App;
