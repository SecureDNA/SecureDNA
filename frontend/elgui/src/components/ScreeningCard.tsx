/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faCheck, faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  type ApiError,
  type ApiResponse,
  Card,
  CopyFastaButton,
  type HitOrganism,
  ProgressBar,
  ScreeningVisualization,
  type Sequence,
  unparseSequence,
} from "@securedna/frontend_common";
import { type ReactNode, useEffect, useRef, useState } from "react";
import {
  type ScreeningProgress,
  performScreening,
} from "src/screening/screening";
import { sha256 } from "src/util/hash";

import type { ScreeningWorkerParams } from "src/screening/types";

const semaphores = new Set<Promise<void>>();
const maxConcurrentJobs = 10;

export async function cachedScreening(
  params: ScreeningWorkerParams,
  callback: (progress: ScreeningProgress) => void,
): Promise<void> {
  const sequence = params.sequence;
  const fasta =
    typeof sequence === "string" ? sequence : unparseSequence(sequence);
  const key = `sdna-screening-${await sha256(fasta)}`;
  const cached = sessionStorage.getItem(key);
  if (cached) {
    const result: ApiResponse = JSON.parse(cached);
    callback({ done: true, result });
  } else {
    while (semaphores.size >= maxConcurrentJobs) {
      await Promise.race(semaphores.values());
    }
    const promise = performScreening(params, callback);
    semaphores.add(promise);
    promise.finally(() => semaphores.delete(promise));
  }
}

export const ScreeningResult = ({
  name,
  sequence,
  result,
}: {
  name: string;
  sequence: string | Sequence;
  result?: ApiResponse | { progress: number };
}) => {
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
      <div className="py-2 text-success">
        <FontAwesomeIcon icon={faCheck} className="mr-2" />
        No hazards detected.
      </div>
    );
  } else if ("hits_by_record" in result) {
    contents = (
      <div className="py-2">
        {result.errors?.length ? (
          <>
            <span className="text-error">
              <FontAwesomeIcon icon={faWarning} className="mr-2" />
              An error occurred:{" "}
            </span>
            {result.errors?.map((err, i) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
              <span key={i}>
                {i > 0 && ", "}
                {err.diagnostic}
              </span>
            ))}
          </>
        ) : (
          <>
            <span className="text-error">
              <FontAwesomeIcon icon={faWarning} className="mr-2" />
              {result.hits_by_record?.length
                ? "Hazards detected"
                : "An error occurred"}
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
    <Card className="min-h-[6.2em]">
      <h2>
        <span>{name || "(no name)"}</span>{" "}
        <span className="float-right text-xs font-normal">
          <CopyFastaButton sequence={sequence} />
        </span>
      </h2>
      {contents}
    </Card>
  );
};

export const ScreeningCard = (props: {
  name: string;
  params: ScreeningWorkerParams;
  complete: (organisms: HitOrganism[], errors: ApiError[]) => void;
}) => {
  const [result, setResult] = useState<ApiResponse | { progress: number }>();
  const { params, complete } = props;

  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    const go = async () => {
      cachedScreening(params, (progress) => {
        if (progress.done) {
          const errors = progress.result.errors ?? [];
          setResult(progress.result);
          if (progress.result.synthesis_permission === "granted") {
            complete([], errors);
          } else {
            const organisms =
              progress.result.hits_by_record?.flatMap((record) =>
                record.hits_by_hazard.flatMap((hazard) => hazard.organisms),
              ) ?? [];
            complete(organisms, errors);
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
        const error: ApiError = {
          diagnostic: String(e),
          additional_info: "",
        };
        setResult({
          synthesis_permission: "denied",
          hits_by_record: [],
          warnings: [],
          errors: [error],
        });
        complete([], [error]);
      });
    }
  }, [complete, result, params]);
  return (
    <ScreeningResult
      name={props.name}
      sequence={props.params.sequence}
      result={result}
    />
  );
};
