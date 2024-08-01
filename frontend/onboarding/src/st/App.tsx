/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import * as fa from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import type { SynthesizerTokenFiles } from "@securedna/frontend_common";
import {
  check_manufacturer_cert,
  create_synthesizer_token,
} from "certificates_wasm";
import { useCallback, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { Card } from "../Card";
import { DownloadFile } from "../DownloadFile";

function DownloadFiles(props: {
  baseName: string;
  screening: boolean;
  files: SynthesizerTokenFiles;
}) {
  const [gotSt, setGotSt] = useState(false);
  const [gotPriv, setGotPriv] = useState(false);
  const gotAll = gotSt && gotPriv;

  return (
    <>
      <div className="border border-primary rounded-lg max-w-screen-lg px-8 py-6 space-y-4">
        <h3 className="text-xl">Download your files</h3>
        <ol className="space-y-4 list-decimal ml-6">
          <li>
            <DownloadFile
              mimeType="application/x-pem-file"
              contents={props.files.synthesizer_token_pem}
              name={`${props.baseName}.st`}
              onClick={() => setGotSt(true)}
            />
            —{" "}
            {props.screening ? (
              <>
                This is a <em>synthesizer token</em>. You will provide this file
                to synthclient to make screening requests.
              </>
            ) : (
              <>
                This is a <em>screening token</em>. You will provide this file
                when approving an exemption token request containing sequences
                that need to be screened.
              </>
            )}
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
        </ol>
        <p>
          Once you have downloaded your files, you can{" "}
          {props.screening ? (
            <>
              use your token in the <i>exemption approval tool</i>.
            </>
          ) : (
            <>
              continue following the Quickstart Guide, starting from
              <em>Running synthclient</em>.
            </>
          )}
        </p>
        <a
          className={
            gotAll
              ? "btn !no-underline"
              : "btn !no-underline opacity-50 cursor-default"
          }
          href={
            gotAll
              ? props.screening
                ? "https://pages.securedna.org/exemption/approve/"
                : "https://pages.securedna.org/production/assets/Synthclient-quickstart.pdf"
              : undefined
          }
        >
          Continue
        </a>
      </div>
    </>
  );
}

function UploadPem(props: {
  title: string;
  header: string;
  accept: string;
  onUpload: (pem: string) => void;
}) {
  const inputRef = useRef(null);
  const [uploadError, setUploadError] = useState("");
  const { accept, header, title, onUpload } = props;

  const onUploadFile = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      if (event.target.files?.[0]) {
        const reader = new FileReader();
        reader.onload = (loaded) => {
          const result = loaded.target?.result;
          if (result && result instanceof ArrayBuffer) {
            const pem = new Uint8Array(result);
            const pemString = new TextDecoder().decode(pem).trim();
            if (!pemString.startsWith(header)) {
              setUploadError(
                `Invalid PEM file. Upload a file starting with: ${header}`,
              );
              onUpload("");
              event.target.value = "";
              return;
            }
            try {
              onUpload(pemString);
              setUploadError("");
            } catch (e) {
              setUploadError(`Could not parse PEM file: ${e}`);
              onUpload("");
              event.target.value = "";
            }
          } else {
            setUploadError("Could not parse PEM file.");
            onUpload("");
            event.target.value = "";
          }
        };
        reader.readAsArrayBuffer(event.target.files[0]);
      }
    },
    [onUpload, header],
  );

  return (
    <div className="flex-1">
      <h3>
        {title} ({accept})
      </h3>
      <p>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          onChange={onUploadFile}
        />
      </p>
      {uploadError && <p className="text-red">{uploadError}</p>}
    </div>
  );
}

type TokenPurpose = "centralized" | "benchtop" | "screening";

interface FormValues {
  purpose: TokenPurpose;
  certPassphrase: string;
  domain: string;
  model: string;
  serial: string;
  rateLimit: string;
  tokenPassphrase: string;
  confirmTokenPassphrase: string;
  daysValid: string;
}

enum CertStatus {
  Empty = 0,
  Pending = 1,
  Ok = 2,
  Error = 3,
}

function defaultPurpose(): TokenPurpose {
  switch (new URLSearchParams(window.location.search).get("purpose")) {
    case "benchtop":
      return "benchtop";
    case "screening":
      return "screening";
    default:
      return "centralized";
  }
}

function CertSummary(props: { status: CertStatus; summary: string }) {
  const { status, summary } = props;
  const [className, icon] =
    status === CertStatus.Pending
      ? ["text-black opacity-50", fa.faHourglass]
      : status === CertStatus.Ok
        ? ["text-[green]", fa.faCheck]
        : ["text-red", fa.faWarning];
  return (
    <p className={className}>
      <FontAwesomeIcon icon={icon} /> {summary}
    </p>
  );
}

function App() {
  const { register, watch, handleSubmit, formState } = useForm<FormValues>({
    defaultValues: { purpose: defaultPurpose() },
  });
  const [busy, setBusy] = useState(false);
  const [files, setFiles] = useState<SynthesizerTokenFiles>();

  const [certPem, setCertPem] = useState("");
  const [privPem, setPrivPem] = useState("");
  const [certStatus, setCertStatus] = useState(CertStatus.Empty);
  const [certSummary, setCertSummary] = useState("");

  const [error, setError] = useState("");
  const watchDaysValid = watch("daysValid", "90");
  const watchPurpose = watch("purpose", defaultPurpose());

  const onSubmit = useCallback(
    (data: FormValues) => {
      if (!certPem) {
        setError("Upload a manufacturer cert.");
        return;
      }
      if (!privPem) {
        setError("Upload a manufacturer private key.");
        return;
      }
      if (data.tokenPassphrase !== data.confirmTokenPassphrase) {
        setError("Enter the same new token passphrase twice.");
        return;
      }
      if (data.tokenPassphrase === data.certPassphrase) {
        setError("New token passphrase must not equal cert passphrase.");
        return;
      }
      if (data.tokenPassphrase.length < 10) {
        setError("New token passphrase should be at least 10 characters long.");
        return;
      }
      setError("");
      setBusy(true);
      setTimeout(() => {
        let files: SynthesizerTokenFiles;
        try {
          files = create_synthesizer_token({
            domain: data.domain,
            model:
              data.purpose === "screening"
                ? "{BSO}"
                : data.purpose === "centralized"
                  ? ""
                  : data.model,
            serial:
              data.purpose === "screening"
                ? "{BSO}"
                : data.purpose === "centralized"
                  ? ""
                  : data.serial,
            rate_limit: Number(data.rateLimit),
            audit_email: null,
            audit_public_key: null,
            token_passphrase: data.tokenPassphrase,
            cert_pem: certPem,
            cert_private_key_pem: privPem,
            cert_passphrase: data.certPassphrase,
            days_valid: Number(data.daysValid),
          });
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
    },
    [privPem, certPem],
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
          If you are a <strong>biosafety officer</strong> in charge of approving
          synthesis exemptions, you should make a single token, and use that
          token in your approvals.
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
              setCertSummary("");
              setCertPem(pem);
            }}
          />
          <UploadPem
            title="Private key"
            header="-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----"
            accept=".priv"
            onUpload={(pem) => {
              setCertStatus(CertStatus.Empty);
              setCertSummary("");
              setPrivPem(pem);
            }}
          />
        </div>
        <p>
          <label>Manufacturer certificate passphrase:</label>{" "}
          <input
            {...register("certPassphrase", { required: true })}
            className="input"
            type="password"
            onBlur={(e) => {
              setCertStatus(CertStatus.Pending);
              setCertSummary("Checking cert...");
              setTimeout(() => {
                try {
                  const summary = check_manufacturer_cert(
                    certPem,
                    privPem,
                    e.target.value,
                  );
                  setCertStatus(CertStatus.Ok);
                  setCertSummary(summary);
                } catch (e) {
                  setCertStatus(CertStatus.Error);
                  setCertSummary(String(e));
                }
              }, 1);
            }}
          />
        </p>
        {certStatus !== CertStatus.Empty && (
          <CertSummary status={certStatus} summary={certSummary} />
        )}
      </Card>
      <fieldset>
        <legend className="my-4">Select the purpose of your token:</legend>
        <Card>
          <div>
            <input
              type="radio"
              value="centralized"
              id="centralized"
              {...register("purpose")}
            />
            <label className="ml-2" htmlFor="centralized">
              I am a centralized provider making a single token for all my
              screening.
            </label>
          </div>
          <div>
            <input
              type="radio"
              value="benchtop"
              id="benchtop"
              {...register("purpose")}
            />
            <label className="ml-2" htmlFor="benchtop">
              I am making a token for a single hardware synthesizer.
            </label>
          </div>
          <div>
            <input
              type="radio"
              value="screening"
              id="screening"
              {...register("purpose")}
            />
            <label className="ml-2" htmlFor="screening">
              I am a BSO making a token for screening exemption token requests.
            </label>
          </div>
        </Card>
      </fieldset>
      <p>
        Then, configure the{" "}
        {watchPurpose === "screening" ? "screening" : "synthesizer"} token
        below.
      </p>
      <Card>
        <h3 className="text-xl">Token configuration</h3>
        <p>
          <label>Domain:</label>{" "}
          <input
            {...register("domain", { required: true })}
            className="input"
            type="text"
            placeholder="yourcompany.com"
          />
        </p>
        {watchPurpose === "benchtop" && (
          <div className="flex flex-col md:flex-row gap-4">
            <p className="flex-1">
              <label>Model:</label>{" "}
              <input
                className="input"
                type="text"
                {...register("model", { required: true })}
                placeholder="DNA Maker 1000"
              />
            </p>
            <p className="flex-1">
              <label>Serial:</label>{" "}
              <input
                className="input"
                type="text"
                {...register("serial", { required: true })}
                placeholder="DM-1234"
              />
            </p>
          </div>
        )}
        <div className="flex flex-col md:flex-row gap-4">
          <p className="flex-1">
            <label>Rate limit (nucleotides per day):</label>{" "}
            <input
              className="input"
              type="number"
              min={0}
              {...register("rateLimit", { required: true, min: 0 })}
            />
          </p>
          <p className="flex-1">
            <label>Days valid:</label>{" "}
            <input
              className="input"
              type="number"
              defaultValue={90}
              min={0}
              max={999}
              {...register("daysValid", { required: true })}
            />
            {watchDaysValid && /^[0-9]{1,3}$/.test(watchDaysValid) && (
              <span>
                Token will be valid until{" "}
                <b>
                  {new Date(
                    Date.now() + Number(watchDaysValid) * 86400000,
                  ).toLocaleDateString("en-US", {
                    month: "long",
                    day: "numeric",
                    year: "numeric",
                  })}
                </b>
              </span>
            )}
          </p>
        </div>
        <p>
          <label>New passphrase for token:</label>{" "}
          <input
            className="input"
            type="password"
            {...register("tokenPassphrase", { required: true })}
          />
        </p>
        <p>
          <label>Confirm new passphrase for token:</label>{" "}
          <input
            className="input"
            type="password"
            {...register("confirmTokenPassphrase", { required: true })}
          />
        </p>
      </Card>
      {error && (
        <p className="text-red">
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
