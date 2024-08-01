/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  faCheck,
  faCopy,
  faDownload,
  faTimes,
  faWarning,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import type { ReactNode } from "react";
import type {
  ApiResponse,
  ApiError as ErrorType,
  ApiWarning as WarningType,
} from "../..";
import { copyToClipboard, download } from "../..";
import { GroupVisualization } from "./GroupVisualization";
import { ExampleHitRectangle } from "./HitRectangle";

export interface ScreeningVisualizationProps {
  result: ApiResponse | { error: { description: string; reason: string } };
  compact?: boolean;
}

const Failure = (props: { children: ReactNode }) => (
  <div className="bg-red-200 p-4 text-xl text-center">{props.children}</div>
);

const Warning = (props: { children: ReactNode }) => (
  <div className="bg-yellow-200 p-4 text-xl text-center">{props.children}</div>
);

const Success = (props: { children: ReactNode }) => (
  <div className="bg-green-200 p-4 text-xl text-center">{props.children}</div>
);

const Button = (props: any) => {
  const { children, ...rest } = props;
  return (
    <button
      type="button"
      className="border text-white border-white hover:opacity-50 transition-opacity rounded-lg p-2"
      {...rest}
    >
      {children}
    </button>
  );
};

interface DiagnosticsProps {
  diagnostics: (WarningType | ErrorType)[];
}

const Diagnostics = ({ diagnostics }: DiagnosticsProps) => (
  <pre className="whitespace-pre-wrap">
    {diagnostics.map((x) => `${x.diagnostic}: ${x.additional_info}`).join("\n")}
  </pre>
);

export const ScreeningVisualization = (props: ScreeningVisualizationProps) => {
  const { result, compact } = props;
  let warnings = undefined;

  if ("error" in result) {
    const { description, reason } = result.error;
    return (
      <Failure>
        An error occurred: {description}
        {reason ? ` (${reason})` : ""}.
      </Failure>
    );
  }
  if ("errors" in result && result.errors) {
    return (
      <Failure>
        <FontAwesomeIcon icon={faTimes} className="mr-3" />
        An error occurred:
        <br />
        <Diagnostics diagnostics={result.errors} />
      </Failure>
    );
  }
  if ("warnings" in result && result.warnings) {
    warnings = (
      <Warning>
        <FontAwesomeIcon icon={faWarning} className="mr-3" />
        Warnings:
        <br />
        <Diagnostics diagnostics={result.warnings} />
      </Warning>
    );
  }
  if (result.synthesis_permission === "granted") {
    return (
      <Success>
        {warnings}
        <FontAwesomeIcon icon={faCheck} className="mr-3" />
        Permission granted
      </Success>
    );
  }
  const groupCount = result.hits_by_record?.length;
  if (!groupCount) {
    return (
      <Failure>
        <FontAwesomeIcon icon={faTimes} className="mr-3" />
        Your request was denied, but no further information is available.
      </Failure>
    );
  }

  return (
    <div className="flex flex-col">
      {!compact && (
        <div className="bg-primary text-white rounded-lg py-4 px-8">
          {warnings}
          <div className="p-4 text-white text-xl text-center">
            <FontAwesomeIcon icon={faTimes} className="mr-3" />
            Your request was denied. Detected hazards are shown below.
          </div>
          <div className="flex justify-between">
            <div className="flex space-x-2 items-end">
              <Button
                onClick={() =>
                  copyToClipboard(
                    "JSON screening result",
                    JSON.stringify(result),
                  )
                }
              >
                <FontAwesomeIcon icon={faCopy} className="mx-2" />
                Copy JSON
              </Button>
              <Button
                onClick={() =>
                  download(
                    JSON.stringify(result),
                    "application/json",
                    "screening-result.json",
                  )
                }
              >
                <FontAwesomeIcon icon={faDownload} className="mx-2" />
                Download JSON
              </Button>
            </div>
            <div className="rounded-lg items-center text-white px-8 flex flex-col justify-center">
              <span>Hover over an organism name to inspect hits:</span>
              <div className="flex mt-2">
                Wild-type
                <div className="w-8 ml-2 mr-12 h-6 relative">
                  <ExampleHitRectangle isWildType={true} />
                </div>
                Functional variant
                <div className="w-8 ml-2 h-6 relative">
                  <ExampleHitRectangle isWildType={false} />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      {result.hits_by_record?.map((group, index) => {
        return (
          <div
            // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
            key={index}
            className={compact ? "" : "px-4 py-2 mt-4 bg-black/5 rounded-lg"}
          >
            <GroupVisualization index={index} group={group} compact={compact} />
          </div>
        );
      })}
    </div>
  );
};
