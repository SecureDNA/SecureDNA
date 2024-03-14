/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { HitOrganism, Sequence } from "@securedna/frontend_common";
import { useEffect, useState } from "react";
import { Button, PrimaryButton, ScreeningCard } from "src/components";
import { useApprovalStore } from "./store";

interface NamedSequence {
  organismName: string;
  sequence: Sequence;
}

const ScreeningPage = () => {
  let sequences: NamedSequence[] = [];
  const eltr = useApprovalStore((state) => state.eltr)!;
  const apiKey = useApprovalStore((state) => state.apiKey);
  const screenedExemptions = useApprovalStore(
    (state) => state.screenedExemptions
  );
  const setScreenedExemptions = useApprovalStore(
    (state) => state.setScreenedExemptions
  );
  const back = useApprovalStore((state) => state.back);
  const advance = useApprovalStore((state) => state.advance);

  for (const organism of eltr.V1.exemptions) {
    for (const sequenceIdentifier of organism.sequences) {
      if ("Dna" in sequenceIdentifier) {
        sequences.push({
          organismName: organism.name,
          sequence: sequenceIdentifier.Dna,
        });
      }
    }
  }
  const [completeCount, setCompleteCount] = useState(0);
  const beforeUnloadHandler = (e: BeforeUnloadEvent) => {
    const message = "If you leave the page, screening progress will be lost.";
    (e || window.event).returnValue = message;
    return message;
  };
  useEffect(() => {
    window.addEventListener("beforeunload", beforeUnloadHandler);
    return () => {
      window.removeEventListener("beforeunload", beforeUnloadHandler);
    };
  }, []);

  const onComplete = (organisms: HitOrganism[]): void => {
    setCompleteCount((n) => {
      if (n + 1 === sequences.length) {
        window.removeEventListener("beforeunload", beforeUnloadHandler);
      }
      return n + 1;
    });

    let updated = new Map(screenedExemptions);
    for (const organism of organisms) {
      const old = updated.get(organism.name) ?? new Set();
      const combined = [...old, ...organism.ans];
      updated.set(organism.name, new Set(combined));
    }
    setScreenedExemptions(updated);
  };

  return (
    <div>
      <h2>Screening</h2>
      {sequences.length > 0 ? (
        <>
          <p className="my-2">
            SecureDNA is now screening the requested FASTA sequences, to decide
            which hazards to grant exemptions for. This may take a long time if
            the sequences are large.
          </p>
          <p className="my-2">
            Exemptions will be granted for the organisms described on the
            previous page, in addition to any detected in screening below.
          </p>
          <div className="my-4">
            {sequences.map((x, i) => (
              <ScreeningCard
                apiKey={apiKey}
                name={x.organismName}
                key={i}
                sequence={x.sequence}
                complete={onComplete}
              />
            ))}
          </div>{" "}
        </>
      ) : (
        <p className="my-2">
          This request does not contain any custom FASTA sequences, so nothing
          needs to be screened. Exemptions will be granted for the organisms
          described on the previous page.
        </p>
      )}
      <p className="my-2">
        If this seems correct, you can approve this request by creating a token
        that the requestor can use for synthesis.
      </p>
      <div className="flex justify-center space-x-2">
        <Button
          type="button"
          disabled={completeCount < sequences.length}
          className="flex-1 my-2 py-3"
          onClick={back}
        >
          Back
        </Button>
        <PrimaryButton
          type="button"
          disabled={completeCount < sequences.length}
          className="flex-[2] my-2 py-3"
          onClick={advance}
        >
          Sign token
        </PrimaryButton>
      </div>
    </div>
  );
};

export default ScreeningPage;
