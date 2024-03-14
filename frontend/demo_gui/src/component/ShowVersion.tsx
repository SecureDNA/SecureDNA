/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import React, { useState, useEffect } from "react";
import axios from "axios";

export default function ShowVersion(props: { baseUrl?: string }) {
  const [synthClientVersion, setSynthClientVersion] = useState("");
  const [hdbTimestamp, setHdbTimestamp] = useState("");

  const { baseUrl } = props;

  useEffect(() => {
    setSynthClientVersion("");
    setHdbTimestamp("");
    if (!baseUrl) {
      return;
    }
    axios
      .get(baseUrl + "/version")
      .then((response) => {
        setSynthClientVersion(response.data["synthclient_version"]);
        setHdbTimestamp(response.data["hdb_timestamp"] ?? "UNKNOWN");
      })
      .catch((err) => console.error(err)); // TODO: better error handling
  }, [baseUrl]);

  return (
    <div className="flex flex-row gap-2 opacity-60">
      {baseUrl ? (
        <>
          <span>client: {synthClientVersion || "loading..."}</span>
          <span>database: {hdbTimestamp || "loading..."}</span>
        </>
      ) : (
        <span>synthclient url not specified</span>
      )}
    </div>
  );
}
