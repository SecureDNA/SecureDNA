/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faQuestionCircle, faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import axios from "axios";
import { useEffect, useState } from "react";

export default function ShowVersion(props: {
  baseUrl?: string;
}) {
  const [synthClientVersion, setSynthClientVersion] = useState("");
  const [hdbTimestamp, setHdbTimestamp] = useState("");
  const [isError, setIsError] = useState(false);

  const { baseUrl } = props;

  useEffect(() => {
    setIsError(false);
    setSynthClientVersion("");
    setHdbTimestamp("");
    if (!baseUrl) {
      return;
    }
    axios
      .get(`${baseUrl}/version`)
      .then((response) => {
        setIsError(false);
        setSynthClientVersion(response.data.synthclient_version);
        setHdbTimestamp(response.data.hdb_timestamp ?? "UNKNOWN");
      })
      .catch((err) => {
        console.log(err);
        setIsError(true);
        setSynthClientVersion("failed to connect");
        setHdbTimestamp("failed to connect");
      });
  }, [baseUrl]);

  return (
    <div className="flex flex-row gap-2 opacity-60 items-center mt-2">
      {isError && <FontAwesomeIcon icon={faWarning} className="text-warn" />}
      {isError ? (
        "Failed to connect."
      ) : baseUrl ? (
        <>
          <span>client: {synthClientVersion || "loading..."}</span>
          <span>database: {hdbTimestamp || "loading..."}</span>
        </>
      ) : (
        <span>synthclient url not specified</span>
      )}
      {isError && (
        <a href="https://github.com/SecureDNA/SecureDNA-dev/wiki/Synthclient-quickstart:-Running-synthclient#connecting-to-synthclient">
          <FontAwesomeIcon icon={faQuestionCircle} className="ml-4 mr-2" />
          Quickstart guide
        </a>
      )}
    </div>
  );
}
