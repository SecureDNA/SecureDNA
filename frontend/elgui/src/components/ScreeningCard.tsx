/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faCheck, faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  ApiResponse,
  HitOrganism,
  ScreeningVisualization,
  Sequence,
} from "@securedna/frontend_common";
import { ReactNode, useEffect, useState } from "react";
import { ScreeningProgress, performScreening } from "src/screening/screening";
import { sha256 } from "src/util/hash";

import { unparse } from "src/util/sequence";
import { CopyFastaButton } from "./CopyFastaButton";
import { ProgressBar } from "./ProgressBar";

async function cachedScreening(
  sequence: string | Sequence,
  apiKey: string,
  callback: (progress: ScreeningProgress) => void
): Promise<void> {
  const fasta = typeof sequence === "string" ? sequence : unparse(sequence);
  const key = "sdna-screening-" + (await sha256(fasta));
  const cached = sessionStorage.getItem(key);
  if (cached) {
    const result: ApiResponse = JSON.parse(cached);
    callback({ done: true, result });
  } else {
    performScreening({ sequence, apiKey }, (p) => {
      if (p.done) {
        try {
          // sessionStorage.setItem(key, JSON.stringify(shrinkResult(p.result)));
        } catch (e) {
          console.warn("sessionStorage is full");
        }
      }
      callback(p);
    });
  }
}

export const ScreeningCard = (props: {
  apiKey: string;
  name: string;
  sequence: Sequence;
  complete: (organisms: HitOrganism[]) => void;
}) => {
  const [result, setResult] = useState<ApiResponse | { progress: number }>();

  useEffect(() => {
    const go = async () => {
      const sequence = props.sequence;

      cachedScreening(sequence, props.apiKey, (progress) => {
        if (progress.done) {
          setResult(progress.result);
          if (progress.result.synthesis_permission === "granted") {
            props.complete([]);
          } else {
            const organisms = progress.result.hits_by_record!.flatMap(
              (record) =>
                record.hits_by_hazard.flatMap((hazard) => hazard.organisms)
            );
            props.complete(organisms);
          }
        } else {
          setResult((old) => ({
            progress:
              (old && "progress" in old ? old.progress : 0) + progress.progress,
          }));
        }
      });
    };

    if (result === undefined) {
      go().catch((e) => {
        console.error(e);
        setResult({
          synthesis_permission: "denied",
          hits_by_record: [],
          warnings: [],
          errors: [{ diagnostic: String(e), additional_info: "" }],
        });
        props.complete([]);
      });
    }
  }, []);

  let contents: ReactNode;
  if (!result) {
    contents = (
      <div className="py-4">
        <ProgressBar percentage={0} />
      </div>
    );
  } else if ("error" in result) {
    contents = <pre>Error: {JSON.stringify(result.error)}</pre>;
  } else if ("progress" in result) {
    const percentage = Math.round(result.progress * 100);
    contents = (
      <div className="py-4">
        <ProgressBar percentage={percentage} />
      </div>
    );
  } else if (result.synthesis_permission === "granted") {
    contents = (
      <div className="py-2 text-green-500">
        <FontAwesomeIcon icon={faCheck} className="mr-2" />
        No hazards detected.
      </div>
    );
  } else if ("hits_by_record" in result) {
    contents = (
      <div className="py-2">
        {result.errors?.length ? (
          <>
            <span className="text-red-500">
              <FontAwesomeIcon icon={faWarning} className="mr-2" />
              Error:{" "}
            </span>
            {result.errors?.map((err, i) => (
              <span key={i}>
                {i > 0 && ", "}
                {err.diagnostic}
              </span>
            ))}
          </>
        ) : (
          <>
            <span className="text-red-500">
              <FontAwesomeIcon icon={faWarning} className="mr-2" />
              Hazards detected
            </span>
            <ScreeningVisualization result={result} compact={true} />
          </>
        )}
      </div>
    );
  } else {
    contents = <div>Invalid state.</div>;
  }
  return (
    <div className="my-2 border bg-white rounded-xl py-4 px-8 min-h-[6.2em]">
      <h2>
        <span>{props.name || "(no name)"}</span>{" "}
        <span className="float-right text-xs font-normal">
          <CopyFastaButton sequence={props.sequence} />
        </span>
      </h2>
      {contents}
    </div>
  );
};
