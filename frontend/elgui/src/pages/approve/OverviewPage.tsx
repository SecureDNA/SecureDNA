/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { Button, EtrDetail, PrimaryButton } from "@securedna/frontend_common";
import { AuthCard } from "src/components/AuthCard";
import { CheckSubject } from "src/util/checkCert";
import { needsScreening } from "src/util/etr";
import { useApprovalStore } from "./store";

function ContinueWithScreening() {
  const back = useApprovalStore((state) => state.back);
  const advance = useApprovalStore((state) => state.advance);
  const synthTokenPem = useApprovalStore((state) => state.synthTokenPem);
  const setSynthTokenPem = useApprovalStore((state) => state.setSynthTokenPem);
  const privPem = useApprovalStore((state) => state.privPem);
  const setPrivPem = useApprovalStore((state) => state.setPrivPem);
  const privPassphrase = useApprovalStore((state) => state.privPassphrase);
  const setPrivPassphrase = useApprovalStore(
    (state) => state.setPrivPassphrase,
  );
  const certsOk = synthTokenPem?.ok && privPem?.ok;

  return (
    <div>
      <p className="mt-8 mb-2">
        If the above overview looks correct, SecureDNA will now screen the
        requested sequences for hazards. This is to make sure the sequences
        really are what they claim to be. Upload a{" "}
        <a href="https://securedna.org/synth-token">
          BSA-mode synthesizer token
        </a>{" "}
        to begin.
      </p>
      <AuthCard
        number={undefined}
        title={"Synth token"}
        noun={"synth token"}
        description={'Upload a synth token ("screening token") to screen.'}
        header={"-----BEGIN SECUREDNA SYNTHESIZER TOKEN-----"}
        acceptExtension={".st"}
        setPem={setSynthTokenPem}
        pem={synthTokenPem}
        privPem={privPem}
        setPrivPem={setPrivPem}
        passphrase={privPassphrase}
        setPassphrase={setPrivPassphrase}
        checkSubject={CheckSubject.SynthToken}
      />
      <div className="flex justify-center space-x-2">
        <Button type="button" className="flex-1 my-2 py-3" onClick={back}>
          Back
        </Button>
        <PrimaryButton
          disabled={!certsOk}
          type="button"
          className="flex-2 my-2 py-3"
          onClick={advance}
        >
          Next
        </PrimaryButton>
      </div>
    </div>
  );
}

function ContinueWithoutScreening() {
  const back = useApprovalStore((state) => state.back);
  const advance = useApprovalStore((state) => state.advance);
  return (
    <div>
      <p className="my-2">
        If the above overview looks correct, proceed to the next page to approve
        this request.
      </p>
      <div className="flex justify-center space-x-2">
        <Button type="button" className="flex-1 my-2 py-3" onClick={back}>
          Back
        </Button>
        <PrimaryButton
          type="button"
          className="flex-2 my-2 py-3"
          onClick={advance}
        >
          Next
        </PrimaryButton>
      </div>
    </div>
  );
}

export default function OverviewPage() {
  const etr = useApprovalStore((state) => state.etr);
  if (!etr) return "OverviewPage without etr";
  const willScreen = needsScreening(etr);

  return (
    <div>
      <EtrDetail etr={etr} />
      {willScreen ? <ContinueWithScreening /> : <ContinueWithoutScreening />}
    </div>
  );
}
