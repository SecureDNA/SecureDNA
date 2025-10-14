/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  faCheck,
  faEllipsis,
  faWarning,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import type {
  BundleCheckError,
  BundleCheckResult,
  CertBundlePreIssuanceError,
  CertCheckResult,
  CertificateDigest,
  ChainItemDigest,
  ChainItemDigestValidationError,
  ExemptionTokenDigest,
  Id,
  InvalidityCause,
} from "..";
import { copyToClipboard } from "..";
import { LinkButton } from "./LinkButton";

function errorMessage(
  noun: string,
  error: Exclude<
    BundleCheckError | CertBundlePreIssuanceError,
    { Chain: any } | { InvalidCert: any }
  >,
): string {
  switch (error) {
    case "CouldNotParseKey":
      return "The private key file could not be parsed. Perhaps you uploaded the wrong file, or it's outdated or corrupted.";
    case "IncorrectPassword":
      return "The passphrase is incorrect.";
    case "KeyMismatch":
      return `The private key does not match the one used to create the ${noun}.`;
    case "NoKey":
      return `The ${noun} does not have an associated keypair, so it cannot be used. Please create a new ${noun}.`;
    case "MissingCert":
      // Should have been caught during parsing -- something is really wrong.
      return `The ${noun} is malformed. Please create a new ${noun}.`;
    case "TraversalLimitReached":
      return "The chain traversal limit was reached without finding a valid path.";
    default:
      return error satisfies never;
  }
}

export const RenderId = ({ id }: { id: Id }) => {
  return (
    <code>
      {id
        .slice(0, 6)
        .map((x) => x.toString(16).padStart(2, "0"))
        .join("")}
    </code>
  );
};

export const RenderCertificateDigest = ({
  digest,
}: { digest: CertificateDigest }) => {
  return (
    <LinkButton
      type="button"
      onClick={() =>
        copyToClipboard("certificate digest", JSON.stringify(digest))
      }
    >
      certificate <RenderId id={digest.request_id} />
    </LinkButton>
  );
};

export const RenderExemptionTokenDigest = ({
  digest,
}: { digest: ExemptionTokenDigest }) => {
  return (
    <LinkButton
      type="button"
      onClick={() =>
        copyToClipboard("certificate digest", JSON.stringify(digest))
      }
    >
      exemption token <RenderId id={digest.request_id} />
    </LinkButton>
  );
};

export const RenderDigest = ({ digest }: { digest: ChainItemDigest }) => {
  return "Certificate" in digest ? (
    <RenderCertificateDigest digest={digest.Certificate} />
  ) : (
    <RenderExemptionTokenDigest digest={digest.ExemptionToken} />
  );
};

export const RenderCause = (props: { cause: InvalidityCause }) => {
  if (typeof props.cause === "object") {
    return props.cause.ValidityPeriod === "Expired"
      ? "The certificate has expired."
      : "The certificate is not yet valid.";
  }
  switch (props.cause) {
    case "Revoked":
      return "This certificate has been revoked.";
    case "SignatureFailure":
      return "The signature is invalid.";
    default:
      return props.cause satisfies never;
  }
};

export const ChainFeedback = (props: {
  item: ChainItemDigestValidationError;
}) => {
  const { digest, error } = props.item;

  return (
    <span>
      Errors in <RenderDigest digest={digest} />:{" "}
      <ul>
        {error.causes.map((cause, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: order is stable per auth attempt
          <li className="list-disc ml-4" key={i}>
            <RenderCause cause={cause} />
          </li>
        ))}
      </ul>
    </span>
  );
};

export const AuthFeedback = (props: {
  noun: string;
  feedback: BundleCheckResult | CertCheckResult | "loading";
}) => {
  if (props.feedback === "loading") {
    return (
      <p className="text-black/50">
        <FontAwesomeIcon icon={faEllipsis} className="mr-2" />
        Checking authentication...
      </p>
    );
  }
  if ("Ok" in props.feedback) {
    return (
      <p className="text-success">
        <FontAwesomeIcon icon={faCheck} className="mr-2" />
        Passphrase correct
      </p>
    );
  }
  if (typeof props.feedback.Err === "string") {
    return (
      <p className="text-error">
        <FontAwesomeIcon icon={faWarning} className="mr-2" />
        {errorMessage(props.noun, props.feedback.Err)}
      </p>
    );
  }
  if ("Chain" in props.feedback.Err) {
    return (
      <p className="text-error">
        <FontAwesomeIcon icon={faWarning} className="mr-2" />
        {props.feedback.Err.Chain.length
          ? "The certificate chain is invalid for the following reasons:"
          : "The certificate chain is invalid."}
        <ul>
          {props.feedback.Err.Chain.map((e, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: order is stable per auth attempt
            <li className="list-disc ml-8" key={i}>
              <ChainFeedback item={e} />
            </li>
          ))}
        </ul>
      </p>
    );
  }
  const invalidCert = props.feedback.Err.InvalidCert;
  return (
    <p className="text-error">
      <FontAwesomeIcon icon={faWarning} className="mr-2" />
      The certificate chain is invalid: <ChainFeedback item={invalidCert} />
    </p>
  );
};
