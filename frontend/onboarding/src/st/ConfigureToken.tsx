/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { extract_data_from_existing_synth_token } from "certificates_wasm";
import { useId } from "react";
import type {
  UseFormRegister,
  UseFormSetValue,
  UseFormWatch,
} from "react-hook-form";
import { Card } from "../Card";
import LabeledInput from "./LabeledInput";
import { UploadPem } from "./UploadPem";
import type { AuditKeySource, FormValues, TokenPurpose } from "./submit";

export function ConfigureToken(props: {
  register: UseFormRegister<FormValues>;
  setValue: UseFormSetValue<FormValues>;
  watch: UseFormWatch<FormValues>;
  purpose: TokenPurpose;
  auditKeySource: AuditKeySource;
  setAuditKeySource: (auditKeySource: AuditKeySource) => void;
}) {
  const {
    register,
    setValue,
    watch,
    purpose,
    auditKeySource,
    setAuditKeySource,
  } = props;
  const watchDaysValid = watch("daysValid", "90");
  const watchAuditEnabled = watch("auditEnabled", false);
  const watchExistingAuditPubPem = watch("existingAuditPubPem", "");
  const auditEnabledId = useId();

  return (
    <Card>
      <h3 className="text-xl">Token configuration</h3>

      <UploadPem
        title="Optional: Reuse configuration from existing synth token"
        header="-----BEGIN SECUREDNA SYNTHESIZER TOKEN-----"
        accept=".st"
        onUpload={(pem) => {
          const data = extract_data_from_existing_synth_token(pem);
          console.log(data);
          setValue("domain", data.domain);
          setValue("model", data.model);
          setValue("serial", data.serial);
          setValue("rateLimit", data.rate_limit);
          if (data.audit_email) setValue("auditEmail", data.audit_email);
          if (data.audit_public_key_pem)
            setValue("existingAuditPubPem", data.audit_public_key_pem);
        }}
      />
      <LabeledInput
        label="Domain:"
        {...register("domain", { required: true })}
        placeholder="yourcompany.com"
      />
      {purpose === "benchtop" && (
        <div className="flex flex-col md:flex-row gap-4">
          <LabeledInput
            label="Model:"
            className="input"
            type="text"
            {...register("model", { required: true })}
            placeholder="DNA Maker 1000"
          />
          <LabeledInput
            label="Serial:"
            className="input"
            type="text"
            {...register("serial", { required: true })}
            placeholder="DM-1234"
          />
        </div>
      )}
      <div className="flex flex-col md:flex-row gap-4">
        <div className="flex-1">
          <LabeledInput
            label="Rate limit (nucleotides per day):"
            className="input flex-1"
            type="number"
            min={0}
            {...register("rateLimit", { required: true, min: 0 })}
          />
        </div>
        <div className="flex-1">
          <LabeledInput
            label="Days valid:"
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
                  Date.now() + Number(watchDaysValid) * 86_400_000,
                ).toLocaleDateString("en-US", {
                  month: "long",
                  day: "numeric",
                  year: "numeric",
                })}
              </b>
            </span>
          )}
        </div>
      </div>
      <LabeledInput
        label="New passphrase for token:"
        className="input"
        type="password"
        {...register("tokenPassphrase", { required: true })}
      />
      <LabeledInput
        label="Confirm new passphrase for token:"
        className="input"
        type="password"
        {...register("confirmTokenPassphrase", { required: true })}
      />
      <p>
        <label className="flex items-middle gap-2" htmlFor={auditEnabledId}>
          <input
            id={auditEnabledId}
            type="checkbox"
            className="h-6 w-6"
            {...register("auditEnabled", { required: false })}
          />{" "}
          Send audit emails about notable orders, such as controlled organisms
        </label>
      </p>
      {watchAuditEnabled && (
        <div className="flex flex-col gap-4">
          <h2 className="text-xl">Audit email configuration</h2>
          <LabeledInput
            label="Audit email:"
            className="input"
            type="email"
            {...register("auditEmail", { required: false })}
          />
          <p>
            Some synthesis providers, benchtop synthesis manufacturers,
            principal investigators, or biosafety offers require notification
            when an order containing a sequence of concern is produced. To
            enable this, supply an email address here, and these notifications
            will be encrypted and sent to this email address to facilitate
            auditing.
          </p>
          <p>
            You will need to present an <em>audit key</em> (yourname-audit.priv)
            file and its passphrase to view the encrypted contents in the{" "}
            <a href="https://pages.securedna.org/inspect">
              SecureDNA Inspector
            </a>
            . If you don't have an audit key, you can generate one below.
          </p>
          <div className="flex mt-2 gap-4">
            <label htmlFor="useNewKey" className="flex gap-2 items-center">
              <input
                type="radio"
                className="h-4 w-4 align-middle"
                value="new"
                checked={auditKeySource === "new"}
                id="useNewKey"
                onChange={() => setAuditKeySource("new")}
              />
              New audit key
            </label>
            <label htmlFor="useExistingKey" className="flex gap-2 items-center">
              <input
                type="radio"
                className="h-4 w-4 align-middle"
                value="existing"
                checked={auditKeySource === "existing"}
                id="useExistingKey"
                disabled={!watchExistingAuditPubPem}
                onChange={() => setAuditKeySource("existing")}
              />
              Inherit key from uploaded synth token
            </label>
          </div>
          <div>
            {auditKeySource === "new" ? (
              <div className="flex flex-col gap-4">
                <LabeledInput
                  label="To generate a new key and attach it to this token, choose a passphrase for the new key:"
                  className="input"
                  type="password"
                  {...register("auditPassphrase", { required: false })}
                />
                <LabeledInput
                  label="And confirm it:"
                  className="input"
                  type="password"
                  {...register("confirmAuditPassphrase", {
                    required: false,
                  })}
                />
              </div>
            ) : undefined}
          </div>
        </div>
      )}
    </Card>
  );
}
