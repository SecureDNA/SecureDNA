/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import * as common from "@securedna/frontend_common";
import * as screening from "src/screening/screening";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";
import App from "./App";

// Patch in crypto.subtle for the Node test environment.
const crypto = require("crypto");
Object.defineProperty(globalThis.crypto, "subtle", {
  value: crypto.webcrypto.subtle,
});

const cert1234Pem: string = `-----BEGIN SECUREDNA EXEMPTION CERTIFICATE-----
MIIBWaKCAVUwggFRoIIBC6AHgAVMRUFGMYEJRVhFTVBUSU9OooH0oIGDgAhTVUJK
RUNUMYEQ/UgmvvEfZtvnF8iFRIYYRoIghZfkNj2cXtdTsDDM4rErJIb/K8pIos3I
ES+Z3na4HiajGoAESmFja4ESamFja0BzZWN1cmVkbmEub3JnpCcMEmJpbGxAc2Vj
dXJlZG5hLm9yZwwRYm9iQHNlY3VyZWRuYS5vcmehbIAHSVNTVUVSMYEQYfMPUCf4
6DXU0uTWnfSJh6I+gCAIEWRGwLD3YKNCOAhnx70ezVSKb7u9ykzmoPm/uuu9nIEa
SmFtZXMsIGphbWVzQHNlY3VyZWRuYS5vcmejDYAEZS21/4EFASEl0/+kAIFAYLRH
BqBaTNR5yYM8dzesiETrARChul/bQAYOaM+XjXACdWk+wuzGeCno548Nv90MWw1D
Dn9Rphco1XkIwBVZDA==
-----END SECUREDNA EXEMPTION CERTIFICATE-----

-----BEGIN SECUREDNA EXEMPTION CERTIFICATE CHAIN-----
MIIBMjCCAS6hggEqMIIBJqCB4aAGgARJTlQxgQlFWEVNUFRJT06igcugXoAIU1VC
SkVDVDGBEKkUFj8BD9oqD9vYT6EaBgyCIAgRZEbAsPdgo0I4CGfHvR7NVIpvu73K
TOag+b+6672coxyABUphbWVzgRNqYW1lc0BzZWN1cmVkbmEub3JnpAChaYAHSVNT
VUVSMYEQAG/157+Qkx8m9fdLXxi7nqI8gCDcrRCouTGnQlh2aLVkGgqpPPM1/FhO
xeRGQjPaFLyi34EYRnJhbiwgZnJhbkBzZWN1cmVkbmEub3JnowyABGUttfmBBGVS
n/mkAIFALmF19OEK3iKCwKmSD66LidBwO1wVpKCe9KThDA///EhPSTHq68jXT8Le
ERAvvFGsrxknK4+xbvFLns3TOiBYDw==
-----END SECUREDNA EXEMPTION CERTIFICATE CHAIN-----`;

const priv1234Pem: string = `-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----
MIHEMGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBC5ZZyZbMvcN74ds0Oo
FoiFAgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEE6RlXGs1nI7E+lb
MuKBkbMEYMT50QQ4Il2RO76+FyToMHvdBKVThU3dg0QBNBZPD/aLNdtjoqgHlMdx
aOhiVXfB3H97IQCDtyZiy1XGYEKJodSCpP17uYGf7yink/8o9bgdIH1Jvo0TCycF
dgJGjXsBrA==
-----END SECUREDNA ENCRYPTED PRIVATE KEY-----`;

describe("ELGUI", () => {
  let downloadedFile:
    | {
        content: Uint8Array | string | Blob;
        mimeType: string;
        filename: string;
      }
    | undefined;

  beforeEach(() => {
    vi.spyOn(common.ncbi, "title").mockImplementation(async () => "Mocked");
    vi.spyOn(screening, "performScreening").mockImplementation(
      async (seq, cb) => {
        cb({
          done: true,
          result: { synthesis_permission: "granted" },
        });
      }
    );
    vi.spyOn(common, "download").mockImplementation(
      (
        content: Uint8Array | string | Blob,
        mimeType: string,
        filename: string
      ) => {
        downloadedFile = { content, mimeType, filename };
      }
    );
  });

  test(
    "request flow",
    async () => {
      const user = userEvent.setup();
      render(<App />);

      // Fill out the contact info:
      const request = screen.getByRole("link", { name: /Request form/ });
      await user.click(request);
      const startButton = screen.getByRole("button", { name: /Start/ });
      await user.click(startButton);
      const country = screen.getByRole("combobox", { name: /Country/ });
      await user.selectOptions(country, "Spain");
      const email = screen.getByRole("textbox", { name: /E-mail/ });
      await user.type(email, "test@example.org");
      const yubikeyOtp = screen.getByPlaceholderText(/Yubikey OTP/);
      await user.type(yubikeyOtp, "c".repeat(44));
      const yubikeyButton = screen.getByRole("button", { name: /Add Yubikey/ });
      await user.click(yubikeyButton);
      const nextButton = screen.getByRole("button", { name: /Next/ });
      expect(nextButton).toBeEnabled();
      await user.click(nextButton);

      // Check we're on the next page now.
      expect(country).not.toBeInTheDocument();
      expect(email).not.toBeInTheDocument();
      expect(yubikeyOtp).not.toBeInTheDocument();

      // Some organisms:
      const organismName = screen.getByLabelText("Name");
      await user.type(organismName, "SARS-CoV-2");
      await user.keyboard("{Enter}");

      // This should be harmless -- and *not* submit the whole form.
      await user.keyboard("{Enter}");

      expect(screen.getByText("GCA_009858895.3")).toBeInTheDocument();
      expect(screen.getByText("NC_045512.2")).toBeInTheDocument();

      // Add some custom ANs:
      const anField = screen.getByRole("textbox", { name: /Accession number/ });
      const addAn = screen.getByRole("button", { name: /Add AN/ });
      await user.type(anField, "T44444");
      await waitFor(() => expect(addAn).toBeEnabled());
      await user.click(addAn);
      expect(screen.getByText("T44444")).toBeInTheDocument();

      await user.type(anField, "CP005080.1"); // Ricin
      await waitFor(() => expect(addAn).toBeEnabled());
      await user.click(addAn);
      expect(screen.getByText("CP005080.1")).toBeInTheDocument();

      // Add a custom fasta:
      await user.click(screen.getByRole("button", { name: /Add FASTA/ }));
      await user.type(screen.getByRole("textbox", { name: /Source/ }), "AAAAA");
      await user.click(screen.getByRole("button", { name: /Save/ }));
      expect(screen.getByText("1 entry (5 bp)")).toBeInTheDocument();

      await user.click(screen.getByRole("button", { name: /Submit/ }));
      await user.click(screen.getByRole("button", { name: /Download/ }));
      expect(downloadedFile?.filename).toMatch(/Anonymous-....-..-..\.eltr/);
      expect(downloadedFile?.mimeType).toMatch("application/x-pem-file");
      const eltrPem = downloadedFile!.content as Uint8Array;
      expect(new TextDecoder().decode(eltrPem)).toMatch(
        /-----BEGIN SECUREDNA EXEMPTION LIST TOKEN REQUEST-----/
      );
    },
    { timeout: 20000 }
  );

  test(
    "approval flow",
    async () => {
      const eltrPem = new TextEncoder()
        .encode(`-----BEGIN SECUREDNA EXEMPTION LIST TOKEN REQUEST-----
MIGzoIGwgAVFTFRSMYEQU3Io4Ki7NCqWmllB5owWbqJSMFCAClNBUlMtQ29WLTKh
QqERgA9HQ0FfMDA5ODU4ODk1LjOhDYALTkNfMDQ1NTEyLjKhCIAGVDQ0NDQ0oQyA
CkNQMDA1MDgwLjGABkFBQUFBCqMYgACBEHRlc3RAZXhhbXBsZS5vcmeCAIMApByg
GqAYgACAAIAAgACAAIAAgACAAIAAgACAAIAApQkwBwwFU3BhaW4=
-----END SECUREDNA EXEMPTION LIST TOKEN REQUEST-----`);

      const user = userEvent.setup();
      render(<App />);

      const approval = screen.getByRole("link", { name: /Approval form/ });
      await user.click(approval);
      await user.upload(
        document.body.querySelector("input[type=file]")!,
        new File([eltrPem], "my.eltr")
      );

      // All our ELTR data should be on this overview page...
      await screen.findByText(/test@example\.org/);
      screen.getByText(/Spain/);
      screen.getByText(/\bcccccccccccc\b/);
      screen.getByText(/SARS-CoV-2/);
      screen.getByText(/GCA_009858895\.3/);
      screen.getByText(/NC_045512\.2/);
      screen.getByText(/T44444/);
      screen.getByText(/CP005080\.1/);
      const copyFasta = screen.getByRole("button", { name: "Copy FASTA" });
      vi.spyOn(window, "matchMedia").mockImplementation(() => undefined as any);
      await user.click(copyFasta);
      const fasta = await window.navigator.clipboard.readText();
      expect(fasta).toEqual(">\nAAAAA");

      await user.upload(
        document.body.querySelector('input[type=file][accept=".cert"]')!,
        new File([cert1234Pem], "my.cert")
      );

      const apiKey = await screen.findByLabelText(/SecureDNA API key/);
      await user.type(apiKey, "doesn't matter, we'll mock screening");

      const nextButton = screen.getByRole("button", { name: /Next/ });
      expect(nextButton).toBeEnabled();
      await user.click(nextButton);

      const signToken = await screen.findByRole("button", {
        name: /Sign token/,
      });
      await waitFor(() => expect(signToken).toBeEnabled());
      await user.click(signToken);
      await screen.findByText(/Final summary/);
      await user.upload(
        document.body.querySelector('input[type=file][accept=".priv"]')!,
        new File([priv1234Pem], "my.priv")
      );
      await user.type(screen.getByPlaceholderText(/Passphrase/), "1234");
      const signButton = screen.getByRole("button", { name: /Sign and/ });
      expect(signButton).toBeEnabled();

      await user.click(signButton);
      expect(downloadedFile?.filename).toMatch(/Anonymous-....-..-..\.elt/);
      expect(downloadedFile?.mimeType).toMatch("application/x-pem-file");
      const eltPem = downloadedFile!.content as Uint8Array;
      expect(new TextDecoder().decode(eltPem)).toMatch(
        /-----BEGIN SECUREDNA EXEMPTION LIST TOKEN-----/
      );
    },
    { timeout: 20000 }
  );
});
