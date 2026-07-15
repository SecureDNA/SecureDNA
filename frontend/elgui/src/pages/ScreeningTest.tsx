/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { Input, Page } from "@securedna/frontend_common";
import { useEffect, useId, useRef, useState } from "react";
import { ScreeningCard } from "src/components/ScreeningCard";
import useLocalStorageState from "use-local-storage-state";

const influenzaSequence =
  "GGCACATCTGGGGTGGAGTCTGCTGTCCTTAAGCATCAATGAACTGAGCAATGTTGGTAATGAAACGAAAACGGGACTCTAGCATAGTACTGACAGCCAGACAGCGACCAAAAGAATTCGGATGGCCATCAATTAGTACTGACAGCCAGACAGCGACCAAAAGAATTCGGATGGCCATCAATTAGTACTGACAGCCAGACAGCGACCAAAAGAATTCGGATGGCCATCAATTAG";

export default function ScreeningTest() {
  const [synthTokenStatus, setSynthTokenStatus] = useState(
    "Loading synth token...",
  );
  const [synthTokenContents, setSynthTokenContents] = useState<Uint8Array>();
  const [privStatus, setPrivStatus] = useState("Loading private key...");
  const [privContents, setPrivContents] = useState<Uint8Array>();
  const [sequence, setSequence] = useLocalStorageState<string>(
    "screening-test-sequence",
    { defaultValue: influenzaSequence },
  );
  const [privPassphrase, setPrivPassphrase] = useLocalStorageState<string>(
    "screening-test-priv-passphrase",
  );

  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    fetch("/elgui/screening.st")
      .then(async (response) => {
        const array = await response.arrayBuffer();
        setSynthTokenContents(new Uint8Array(array));
        setSynthTokenStatus(
          `Loaded /elgui/views/public/screening.st (${array.byteLength} bytes)`,
        );
      })
      .catch(() => {
        setSynthTokenStatus(
          "Put a synth token signed to the prod root at /elgui/views/public/screening.st",
        );
      });
    fetch("/elgui/screening.priv")
      .then(async (response) => {
        const array = await response.arrayBuffer();
        setPrivContents(new Uint8Array(array));
        setPrivStatus(
          `Loaded /elgui/views/public/screening.priv (${array.byteLength} bytes)`,
        );
      })
      .catch(() => {
        setPrivStatus(
          "Put the private key of synth token signed to the prod root at /elgui/views/public/screening.priv",
        );
      });
  }, []);

  const privateKeyId = useId();
  const sequenceId = useId();

  return (
    <Page title="Screening Test">
      <div className="w-full max-w-3xl my-4 px-2 flex flex-col">
        <h2>WebAssembly Screening Test</h2>
        <form className="flex flex-col gap-4">
          <div>{synthTokenStatus}</div>
          <div>{privStatus}</div>
          <label htmlFor={privateKeyId}>
            Private key passphrase
            <Input
              id={privateKeyId}
              type="password"
              value={privPassphrase ?? ""}
              onChange={(e) => setPrivPassphrase(e.target.value)}
            />
          </label>
          <label htmlFor={sequenceId}>
            Sequence
            <Input
              id={sequenceId}
              type="text"
              value={sequence ?? ""}
              onChange={(e) => setSequence(e.target.value)}
            />
          </label>
        </form>
        {synthTokenContents?.length &&
        privContents?.length &&
        privPassphrase ? (
          <ScreeningCard
            name={"Screening test"}
            key={privPassphrase}
            params={{
              sequence,
              synthTokenContents,
              privContents,
              privPassphrase,
            }}
            complete={() => {}}
          />
        ) : (
          <div className="text-red-500">
            Missing token, private key, or passphrase.
          </div>
        )}
      </div>
    </Page>
  );
}
