/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { AuthCard, Button, EltrDetail, PrimaryButton } from "src/components";
import { needsScreening } from "src/util/eltr";
import { useApprovalStore } from "./store";

export default function OverviewPage() {
  const certPem = useApprovalStore((state) => state.certPem);
  const setCertPem = useApprovalStore((state) => state.setCertPem);
  const apiKey = useApprovalStore((state) => state.apiKey);
  const setApiKey = useApprovalStore((state) => state.setApiKey);
  const eltr = useApprovalStore((state) => state.eltr);
  const back = useApprovalStore((state) => state.back);
  const advance = useApprovalStore((state) => state.advance);
  if (!eltr) return undefined;
  const certOk = certPem && certPem.ok;
  const willScreen = needsScreening(eltr);

  return (
    <div>
      <EltrDetail eltr={eltr} />
      <h2>Upload certificate</h2>
      {willScreen ? (
        <p className="my-2">
          If the above overview looks correct, SecureDNA will now screen the
          requested sequences for hazards. This is to make sure the sequences
          really are what they claim to be. Upload a SecureDNA certificate to
          begin.
        </p>
      ) : (
        <p>
          To continue approving this request, provide your SecureDNA
          certificate.
        </p>
      )}
      <div className="px-16 my-4">
        <AuthCard
          number={undefined}
          title={"Certificate"}
          description={
            willScreen
              ? "Identify yourself to request screening."
              : "Identify yourself to approve this request."
          }
          header="-----BEGIN SECUREDNA EXEMPTION CERTIFICATE-----"
          acceptExtension={".cert"}
          setPem={setCertPem!}
          pem={certPem!}
        />
      </div>
      <p className="my-2">
        If you don't have a .cert file, contact your administrator.
      </p>
      <p className="my-2">
        Enter your{" "}
        <label>
          SecureDNA API key:{" "}
          <input
            className="px-1 border"
            type="password"
            aria-label="SecureDNA API Key"
            placeholder="smallblue..."
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          ></input>
        </label>
      </p>
      <div className="flex justify-center space-x-2">
        <Button type="button" className="flex-1 my-2 py-3" onClick={back}>
          Back
        </Button>
        <PrimaryButton
          disabled={!certOk}
          type="button"
          className="flex-[2] my-2 py-3"
          onClick={advance}
        >
          Next
        </PrimaryButton>
      </div>
    </div>
  );
}
