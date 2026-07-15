/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { SynthesizerTokenFiles } from "@securedna/frontend_common";
import { useState } from "react";
import { DownloadFile } from "../DownloadFile";

export function DownloadFiles(props: {
  baseName: string;
  screening: boolean;
  files: SynthesizerTokenFiles;
}) {
  const [gotSt, setGotSt] = useState(false);
  const [gotPriv, setGotPriv] = useState(false);
  const [gotAuditPriv, setGotAuditPriv] = useState(
    !props.files.new_audit_private_key_pem,
  );
  const gotAll = gotSt && gotPriv && gotAuditPriv;

  return (
    <>
      <div className="border border-primary rounded-lg max-w-(--breakpoint-lg) px-8 py-6 space-y-4">
        <h3 className="text-xl">Download your files</h3>
        <ol className="space-y-4 list-decimal ml-6">
          <li>
            <DownloadFile
              mimeType="application/x-pem-file"
              contents={props.files.synthesizer_token_pem}
              name={`${props.baseName}.st`}
              onClick={() => setGotSt(true)}
            />
            —{" "}
            {props.screening ? (
              <>
                This is a <em>synthesizer token</em>. You will provide this file
                to synthclient to make screening requests.
              </>
            ) : (
              <>
                This is a <em>screening token</em>. You will provide this file
                when approving an exemption token request containing sequences
                that need to be screened.
              </>
            )}
          </li>
          <li>
            <DownloadFile
              mimeType="application/x-pem-file"
              contents={props.files.private_key_pem}
              name={`${props.baseName}.priv`}
              onClick={() => setGotPriv(true)}
            />
            — This is a <em>private key</em>, protected by your passphrase. Do{" "}
            <strong>not</strong> send this to SecureDNA, do not lose it, and do
            not share it. (If you send it to SecureDNA by mistake, we will ask
            you to generate a new certificate request and to throw away the
            existing request.)
          </li>
          {props.files.new_audit_private_key_pem && (
            <li>
              <DownloadFile
                mimeType="application/x-pem-file"
                contents={props.files.new_audit_private_key_pem}
                name={`${props.baseName}-audit.priv`}
                onClick={() => setGotAuditPriv(true)}
              />
              — This is an <em>audit private key</em>, protected by your audit
              passphrase. You will use it to decrypt audit email attachments in
              the SecureDNA Inspector.
            </li>
          )}
        </ol>
        <p>
          Once you have downloaded your files, you can{" "}
          {props.screening ? (
            <>
              use your token in the <i>exemption approval tool</i>.
            </>
          ) : (
            <>
              continue following the quickstart guide from{" "}
              <a href="https://github.com/SecureDNA/SecureDNA/wiki/Synthclient-quickstart:-Running-synthclient">
                <em>Running synthclient</em>
              </a>
              .
            </>
          )}
        </p>
        <a
          className={
            gotAll
              ? "btn no-underline!"
              : "btn no-underline! opacity-50 cursor-default"
          }
          target="_top"
          href={
            gotAll
              ? props.screening
                ? "https://pages.securedna.org/exemption/approve/"
                : "https://github.com/SecureDNA/SecureDNA/wiki/Synthclient-quickstart:-Running-synthclient"
              : undefined
          }
        >
          Continue
        </a>
      </div>
    </>
  );
}
