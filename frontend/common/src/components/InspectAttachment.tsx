/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { type Attachment, LinkButton } from "..";

interface InspectAttachmentProps {
  attachment: Attachment;
}

function describeFileSize(bytes: number) {
  const fmt = (x: number) =>
    x.toLocaleString(undefined, { maximumFractionDigits: 1 });

  const units: [number, string][] = [
    [1e9, "GB"],
    [1e6, "MB"],
    [1e3, "kB"],
  ];
  for (const [scale, unit] of units) {
    if (bytes >= scale) return `${fmt(bytes / scale)} ${unit}`;
  }
  if (bytes === 1) return "1 byte";
  return `${bytes} bytes`;
}

export function InspectAttachment({ attachment }: InspectAttachmentProps) {
  const bytes = new Uint8Array(attachment.contents);
  const handleDownload = () => {
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = attachment.name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  };

  return (
    <span>
      <LinkButton type="button" onClick={handleDownload}>
        {attachment.name}
      </LinkButton>{" "}
      ({describeFileSize(attachment.contents.length)})
    </span>
  );
}
