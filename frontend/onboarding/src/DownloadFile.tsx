/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faCheck, faDownload } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";

export function DownloadedMarker(props: { downloaded: boolean }) {
  return props.downloaded ? (
    <div className="inline-block relative w-6 ml-1">
      <FontAwesomeIcon icon={faCheck} className="text-[green] animate-appear" />
    </div>
  ) : (
    <div className="inline-block relative w-6 ml-1">
      <div className="absolute w-2 h-2 bg-red animate-ping rounded left-1" />
      <div className="absolute w-2 h-2 bg-red rounded left-1" />
      <FontAwesomeIcon icon={faDownload} className="" />
    </div>
  );
}

export function DownloadFile(props: {
  contents: string;
  mimeType: string;
  name: string;
  onClick?: () => void;
}) {
  const [downloaded, setDownloaded] = useState(false);
  const uri = encodeURIComponent(props.contents);

  return (
    <div className="inline-block mr-2">
      <a
        href={`data:${props.mimeType};charset=utf-8,${uri}`}
        download={props.name}
        onClick={() => {
          setDownloaded(true);
          props.onClick?.();
        }}
      >
        <DownloadedMarker downloaded={downloaded} />

        {props.name}
      </a>
    </div>
  );
}
