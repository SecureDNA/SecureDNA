/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faCheck, faCopy, faDownload } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import type { ReactNode } from "react";
import type {
  ApiResponse,
  ApiError as ErrorType,
  ApiWarning as WarningType,
} from "../..";
import { Card, copyToClipboard, download } from "../..";
import { GroupVisualization } from "./GroupVisualization";
import { ExampleHitRectangle } from "./HitRectangle";

export interface ScreeningVisualizationProps {
  result: ApiResponse | { error: { description: string; reason: string } };
  compact?: boolean;
}

const Failure = (props: { children: ReactNode }) => (
  <Card flavor="warn">{props.children}</Card>
);

const Warning = (props: { children: ReactNode }) => (
  <Card flavor="warn">{props.children}</Card>
);

const Success = (props: { children: ReactNode }) => (
  <Card flavor="primary">{props.children}</Card>
);

const Button = (props: any) => {
  const { children, ...rest } = props;
  return (
    <button
      type="button"
      className="border border-black hover:opacity-50 transition-opacity rounded-lg p-2 cursor-pointer"
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
  <div className="max-w-xl text-base whitespace-pre-wrap my-2 text-sm">
    {diagnostics
      .map((x) =>
        x.additional_info
          ? `${x.diagnostic}: ${x.additional_info}`
          : x.diagnostic,
      )
      .join("\n")}
  </div>
);

export const ScreeningVisualization = (props: ScreeningVisualizationProps) => {
  const { result, compact } = props;
  let warnings = undefined;

  const copyJsonButton = (
    <Button
      onClick={() =>
        copyToClipboard("JSON screening result", JSON.stringify(result))
      }
    >
      <FontAwesomeIcon icon={faCopy} className="mx-2" />
      Copy JSON
    </Button>
  );

  if ("error" in result) {
    const { description, reason } = result.error;
    return (
      <Failure>
        An error occurred: {description}
        {reason ? ` (${reason})` : ""}.
        <br />
        {!compact && copyJsonButton}
      </Failure>
    );
  }
  if ("errors" in result && result.errors) {
    return (
      <Failure>
        <h3 className="font-bold mb-2">An error occurred</h3>
        <Diagnostics diagnostics={result.errors} />
        {!compact && copyJsonButton}
      </Failure>
    );
  }
  if ("warnings" in result && result.warnings) {
    warnings = (
      <div>
        <h3 className="font-bold mb-2">Warnings</h3>
        <Diagnostics diagnostics={result.warnings} />
      </div>
    );
  }
  if (result.synthesis_permission === "granted") {
    return (
      <Success>
        {warnings}
        <p className="my-2">
          <FontAwesomeIcon icon={faCheck} className="mr-3" />
          Permission granted
        </p>
        {!compact && copyJsonButton}
      </Success>
    );
  }
  const groupCount = result.hits_by_record?.length;
  if (!groupCount) {
    return (
      <Failure>
        <p className="my-2">Your request was denied.</p>
        {warnings}
        {!compact && copyJsonButton}
      </Failure>
    );
  }

  return (
    <div className="flex flex-col">
      {!compact && (
        <div className="bg-primary rounded-lg py-4 px-8">
          {warnings}
          <div className="p-4 text-xl text-center">
            Your request was denied. Detected hazards are shown below.
          </div>
          <div className="flex justify-between">
            <div className="flex space-x-2 items-end">
              {copyJsonButton}
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
            <div className="rounded-lg items-center px-8 flex flex-col justify-center">
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
