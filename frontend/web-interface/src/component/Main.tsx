/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import axios from "axios";
import { useEffect, useRef, useState } from "react";
import { Toaster } from "react-hot-toast";
import useLocalStorageState from "use-local-storage-state";

import {
  type ApiResponse,
  type CheckFastaRequest,
  ScreeningVisualization,
  ncbi,
} from "@securedna/frontend_common";
import EtInput, { type EtWithPem } from "./EtInput";
import { FastaInput } from "./FastaInput";
import { NcbiInput } from "./NcbiInput";
import { Setting } from "./Setting";
import ShowVersion from "./ShowVersion";
import Spinner from "./Spinner";
import UrlWarning from "./UrlWarning";

/// For orders at least this many base pairs long, show a confirmation dialog
/// warning how long it will take.
const largeOrderThreshold = 100_000;

/// Orders larger than this many base pairs are simply not allowed.
const maximumOrderLength = 1_000_000;

/// Given the length of an order in base pairs, decide if we should submit it
/// for screening by prompting the user for confirmation on large orders.
function confirmLargeOrder(length: number): boolean {
  if (length < largeOrderThreshold) {
    return true;
  }

  if (length > maximumOrderLength) {
    alert(
      `This ${length.toLocaleString()} bp order exceeds ` +
        `the maximum of ${maximumOrderLength.toLocaleString()} bp.`,
    );
    return false;
  }

  // Empirically, screening 100k bp takes about 3 minutes on our demo hardware.
  const estimatedMinutes = Math.round((length / 100000) * 3);
  return window.confirm(
    `This ${length.toLocaleString()} bp order may take about ` +
      `${estimatedMinutes} minutes to process. Really submit?`,
  );
}

function Main() {
  const [synthClientUrl, setSynthClientUrl] = useSynthClientURL();
  const baseUrl = synthClientUrl?.replace(/\/$/, "");
  const screenUrl = `${baseUrl}/v1/screen`;
  const ncbiUrl = `${baseUrl}/v1/ncbi`;

  const [et, setEt] = useState<EtWithPem>();
  const [yubicoOtp, setYubicoOtp] = useState("");
  const [mode, setMode] = useState<"fasta" | "ncbi">("fasta");
  const [response, setResponse] = useState<ApiResponse | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const urlInputRef = useRef<HTMLInputElement>(null);
  const urlInputFocused =
    urlInputRef.current !== null &&
    document.activeElement === urlInputRef.current;

  const postJsonAndShowResponse = async (url: string, request: string) => {
    setBusy(true);
    axios
      .post(url, request, {
        headers: {
          "Content-Type": "application/json",
        },
      })
      .then((response) => {
        setBusy(false);
        setResponse(response.data as ApiResponse);
      })
      .catch((error: any): void => {
        setBusy(false);
        console.error(error);
        if ("response" in error) {
          setResponse(error.response.data as ApiResponse);
        } else {
          setResponse({
            synthesis_permission: "denied",
            errors: [
              {
                diagnostic: String(error),
                additional_info: "",
              },
            ],
          });
        }
      });
  };

  const getApi = async (fasta: string) => {
    if (!fasta) {
      alert("FASTA input not specified");
      return;
    }
    const length = fasta.replaceAll(/^[>;].*|\n|\s/gm, "").length;
    if (!confirmLargeOrder(length)) {
      return;
    }
    const body: CheckFastaRequest = {
      fasta,
      region: "All",
      ets: et
        ? [{ et: et.pem, requestor_otp: yubicoOtp, issuer_otp: null }]
        : [],
    };
    const request = JSON.stringify(body);
    postJsonAndShowResponse(screenUrl, request);
  };

  const getNcbiApi = async (accession: string) => {
    if (!accession) {
      alert("NCBI Accession number not specified");
      return;
    }
    setBusy(true);
    const length = (await ncbi.length(accession)) ?? 0;
    if (!confirmLargeOrder(length)) {
      setBusy(false);
      return;
    }
    const request = JSON.stringify({
      id: accession.trim(),
      region: "All",
    });
    postJsonAndShowResponse(ncbiUrl, request);
  };

  const buttonClass =
    "border border-primary/50 text-primary hover:bg-primary/20 cursor-pointer rounded px-2 flex-none";

  const disableReason = busy
    ? "Busy…"
    : !synthClientUrl
      ? "Synthclient URL missing"
      : undefined;

  return (
    <div className="w-full flex flex-col items-center gap-10 min-h-screen">
      <Toaster position="top-left" />
      <section className="inset-0 w-full block p-10 bg-gradient-to-br from-primary-dark to-primary text-white">
        <div className="absolute top-0 left-0 p-2">
          <ShowVersion baseUrl={baseUrl} />
        </div>
        <h1 className="text-center font-bold text-3xl">
          SecureDNA Web Interface
        </h1>
      </section>

      <div className="flex flex-col items-center w-full max-w-xl">
        <form className="w-full flex flex-col gap-2">
          <details className="border px-6 py-4 rounded-lg" open={true}>
            <summary>
              Synthclient URL <small>{synthClientUrl}</small>
              {!synthClientUrl && (
                <span className="text-red-600"> (required)</span>
              )}
            </summary>
            <Setting
              label="Synthclient URL"
              required={true}
              input={(props) => (
                <div className="flex gap-1">
                  <input
                    className="flex-1"
                    {...props}
                    value={synthClientUrl || undefined}
                    onChange={(e) => setSynthClientUrl(e.target.value)}
                    spellCheck={false}
                    ref={urlInputRef}
                  />
                  <button
                    type="button"
                    className={buttonClass}
                    onClick={(e) => setSynthClientUrl("http://localhost:80")}
                  >
                    localhost
                  </button>
                </div>
              )}
            />
            <UrlWarning
              setSynthClientUrl={setSynthClientUrl}
              synthClientUrl={synthClientUrl}
            />
          </details>

          <details className="border px-6 py-4 rounded-lg">
            <summary>Exemption token</summary>
            <EtInput
              et={et}
              setEt={setEt}
              yubicoOtp={yubicoOtp}
              setYubicoOtp={setYubicoOtp}
            />
          </details>

          <Setting
            label="Request type"
            input={(props) => (
              <select
                {...props}
                value={mode}
                onChange={(e) => setMode(e.target.value as any)}
              >
                <option value="fasta">FASTA</option>
                <option value="ncbi">Accession number (fetch from NCBI)</option>
              </select>
            )}
          />

          {mode === "fasta" ? (
            <FastaInput
              getApi={getApi}
              disableReason={disableReason}
              onChange={() => setResponse(undefined)}
            />
          ) : (
            <NcbiInput
              getNcbiApi={getNcbiApi}
              disableReason={disableReason}
              onChange={() => setResponse(undefined)}
            />
          )}
        </form>
      </div>

      {busy ? (
        <Spinner />
      ) : (
        !!response && (
          <>
            <h2 className="text-center font-bold text-2xl">Response</h2>
            <div className="mb-16">
              <ScreeningVisualization result={response} />
            </div>
          </>
        )
      )}
    </div>
  );
}

/**
 * Hook that handles sourcing the synthclient URL from query parameters,
 * localStorage, or UI state.
 */
function useSynthClientURL(): [string | null, (url: string) => void] {
  const apiParam = new URLSearchParams(window.location.search).get("api");

  const initialValue = apiParam || null;
  const [synthClientUrl, setSynthClientUrl] = useLocalStorageState(
    "securedna-api-url",
    { defaultValue: initialValue },
  );

  // override the saved state initially if we were redirected here, but otherwise
  // don't change the user's selection
  useEffect(() => {
    if (apiParam && apiParam !== synthClientUrl) {
      setSynthClientUrl(apiParam);
    }
  }, [apiParam, synthClientUrl, setSynthClientUrl]);

  // treat empty string as null
  let normalizedSynthClientUrl: string | null;
  if (synthClientUrl?.trim() === "") {
    normalizedSynthClientUrl = null;
  } else {
    normalizedSynthClientUrl = synthClientUrl?.trim() ?? null;
  }

  return [normalizedSynthClientUrl, setSynthClientUrl];
}

export default Main;
