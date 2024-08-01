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
import { etBundlePemToJsObject } from "./util/sign_etr";

// Patch in crypto.subtle for the Node test environment.
const crypto = require("node:crypto");
Object.defineProperty(globalThis.crypto, "subtle", {
  value: crypto.webcrypto.subtle,
});

const cert1234Pem: string = `-----BEGIN SECUREDNA EXEMPTION CERTIFICATE-----
MIIBZqKCAWIwggFeoIIBGKAHgAVMRUFGMYEJRVhFTVBUSU9OooIBAKCBj4ARRVhF
TVBUSU9OU1VCSkVDVDGBEH2isSL3AlXUZZg6D+t5sQCCIKQJCuWZRgfb7vnP9upJ
YUewga1ITmzHx0SjwRl01R0aoxqABEphY2uBEmphY2tAc2VjdXJlZG5hLm9yZ6Qn
DBJiaWxsQHNlY3VyZWRuYS5vcmcMEWJvYkBzZWN1cmVkbmEub3JnhQEAoWyAB0lT
U1VFUjGBEBbfpiDooxMyAm+aPVLChhSiPoAgRZ3zAm9LbmDH/mNHCvxfSUg1epzm
ywZ05H/hnlbVn7aBGkphbWVzLCBqYW1lc0BzZWN1cmVkbmEub3Jnow2ABGX+Z8GB
BQEh9oXBpACBQFSQYFzeC/t3YzPBOxk7vYLAdloT5nkajifzPjPOhT1ztlnL85Kq
BjAPwe3KrL+sLqKENxEENOxEM7Y5jMyRQwg=
-----END SECUREDNA EXEMPTION CERTIFICATE-----

-----BEGIN SECUREDNA EXEMPTION CERTIFICATE CHAIN-----
MIIBPjCCATqhggE2MIIBMqCB7aAGgARJTlQxgQlFWEVNUFRJT06igdegaoARRVhF
TVBUSU9OU1VCSkVDVDGBECDtc3kftVqNb1PX1OOYkGuCIEWd8wJvS25gx/5jRwr8
X0lINXqc5ssGdOR/4Z5W1Z+2oxyABUphbWVzgRNqYW1lc0BzZWN1cmVkbmEub3Jn
pACFAQChaYAHSVNTVUVSMYEQRJKrOx5j6IRTjanEd4pBPaI8gCCJmOdLRO1IN5iL
j7+6zkLYr4TNeWdvhvlLZOQgP8SaXoEYRnJhbiwgZnJhbkBzZWN1cmVkbmEub3Jn
owyABGX+Z7SBBGYjUbSkAIFAB1/9QSK1jo1rJZVqzyk2VxLxUquhSj5jdmWJqCPp
OvgMHHvi8lyXBhJfFkgBzjJAhmzdhZD28nWM/IMRLEb3DA==
-----END SECUREDNA EXEMPTION CERTIFICATE CHAIN-----`;

const priv1234Pem: string = `-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----
MIHEMGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBB/EEX9YGLjm3Du5m2U
rqVPAgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEAxEM8fbSGJHgcAJ
3huClX4EYBZo0rFJyrE+2+uAkaMaFIM/TSxsCrIFVWNzRMaGN90uYzfi/xNoJZ3E
g/GzY8X1FE+QZmfY1xXOzVFqaC89FYJ41qqXAAXWfZ8kCF98zATSZLJ2WHihDNI2
D1ibYopH3g==
-----END SECUREDNA ENCRYPTED PRIVATE KEY-----`;

const researcherPriv: string = `-----BEGIN SECUREDNA ENCRYPTED PRIVATE KEY-----
MIHEMGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBBX++QDKnIgAS2KkzMw
/207AgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEED6BoIB5WUZW0t0z
ZwxffP8EYErknFmAb8+Eh5Cb76lnPWIo3nn0DBiKWoBsAe+Q/Gl4IJG5BbEbP4a3
ekklxSoYQFKfUsuhtT57YdIrmNlGvMIE70Zfji7opVbXtAQ7jzEzJqDQfWThDG98
5ktB6KthcQ==
-----END SECUREDNA ENCRYPTED PRIVATE KEY-----`;

const researcherPub: string = `2c1aee0592406e75266ab8a44fcfea8d2f2f51cfb229512ace7be0ed617c2ac7
-----BEGIN SECUREDNA PUBLIC KEY-----
BCAsGu4FkkBudSZquKRPz+qNLy9Rz7IpUSrOe+DtYXwqxw==
-----END SECUREDNA PUBLIC KEY-----`;

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
      },
    );
    vi.spyOn(common, "download").mockImplementation(
      (
        content: Uint8Array | string | Blob,
        mimeType: string,
        filename: string,
      ) => {
        downloadedFile = { content, mimeType, filename };
      },
    );
    downloadedFile = undefined;
    const ResizeObserverMock = vi.fn(() => ({
      observe: vi.fn(),
      unobserve: vi.fn(),
      disconnect: vi.fn(),
    }));
    vi.stubGlobal("ResizeObserver", ResizeObserverMock);
  });

  test("end-to-end test", { timeout: 40000 }, async () => {
    const user = userEvent.setup();
    render(<App />);

    // Fill out the contact info:
    const request = screen.getByRole("link", { name: /Request/ });
    await user.click(request);
    const startButton = screen.getByRole("button", { name: /Start/ });
    await user.click(startButton);
    const country = screen.getByRole("combobox", { name: /Country/ });
    await user.selectOptions(country, "Spain");
    const email = screen.getByRole("textbox", { name: /E-mail/ });
    await user.type(email, "test@example.org");

    await user.click(screen.getByRole("button", { name: /New keypair/ }));
    const passphrase = screen.getByPlaceholderText(/Passphrase/);
    await user.type(passphrase, "abcdefghij");
    downloadedFile = undefined as any;
    await user.click(screen.getByRole("button", { name: /Generate/ }));
    await waitFor(() => expect(downloadedFile).toBeTruthy());
    expect(downloadedFile?.filename).toMatch(
      /Anonymous-....-..-..-\w{12}\.priv$/,
    );
    expect(downloadedFile?.mimeType).toMatch("application/x-pem-file");
    const etrPrivateKey = downloadedFile?.content as Uint8Array;

    // await user.upload(
    //   document.body.querySelector("input[type=file]")!,
    //   new File([researcherPub], "my.pub")
    // );
    {
      const yubikeyButton = screen.getByRole("button", {
        name: /Add Yubikey/,
      });
      await user.click(yubikeyButton);
      const yubikeyOtp = screen.getByPlaceholderText(/Yubikey OTP/);
      await user.type(yubikeyOtp, "c".repeat(44));
      const addButton = screen.getByRole("button", { name: /^Add Yubikey$/ });
      await user.click(addButton);
      const nextButton = screen.getByRole("button", { name: /Next/ });
      expect(nextButton).toBeEnabled();

      await user.click(nextButton);

      // Check we're on the next page now.
      expect(country).not.toBeInTheDocument();
      expect(email).not.toBeInTheDocument();
      expect(yubikeyOtp).not.toBeInTheDocument();
    }

    {
      // Some organisms:
      const organismName = screen.getByLabelText("Name");
      await user.type(organismName, "SARS-CoV-2");
      await user.keyboard("{Enter}");

      // This should be harmless -- and *not* submit the whole form.
      await user.keyboard("{Enter}");

      expect(screen.getByText(/GCA_009858895\.3/)).toBeInTheDocument();
      expect(screen.getByText(/NC_045512\.2/)).toBeInTheDocument();
    }

    {
      // Add some custom ANs:
      const anField = screen.getByRole("textbox", {
        name: /Accession number/,
      });
      const addAn = screen.getByRole("button", { name: /Add AN/ });
      await user.type(anField, "T44444");
      await waitFor(() => expect(addAn).toBeEnabled());
      await user.click(addAn);
      expect(screen.getByText(/T44444/)).toBeInTheDocument();

      await user.type(anField, "CP005080.1"); // Ricin
      await waitFor(() => expect(addAn).toBeEnabled());
      await user.click(addAn);
      expect(screen.getByText(/CP005080\.1/)).toBeInTheDocument();

      // Add a custom fasta:
      await user.click(screen.getByRole("button", { name: /Add FASTA/ }));
      await user.type(screen.getByRole("textbox", { name: /Source/ }), "AAAAA");
      await user.click(screen.getByRole("button", { name: /Save/ }));
      expect(screen.getByText(/1 entry \(5 bp\)/)).toBeInTheDocument();

      // Add a second organism:
      await user.click(screen.getByRole("button", { name: /Add organism/ }));
      const newOrganismName = screen.getAllByLabelText("Name").pop()!;
      await user.type(newOrganismName, "Aflatoxins");
      await user.keyboard("{Enter}");
      expect(screen.getByText(/AB076803\.1/)).toBeInTheDocument();
    }

    await user.click(screen.getByRole("button", { name: /Submit/ }));
    await user.click(screen.getByRole("button", { name: /Download/ }));
    await waitFor(() => expect(downloadedFile).toBeTruthy());
    expect(downloadedFile?.filename).toMatch(/Anonymous-....-..-..\.etr$/);
    expect(downloadedFile?.mimeType).toMatch("application/x-pem-file");
    const etrPem = downloadedFile?.content as Uint8Array;
    expect(new TextDecoder().decode(etrPem)).toMatch(
      /-----BEGIN SECUREDNA EXEMPTION TOKEN REQUEST-----/,
    );
    // console.log(new TextDecoder().decode(etrPem));

    const approval = screen.getByRole("link", { name: /Approve/ });
    await user.click(approval);
    await user.upload(
      document.body.querySelector("input[type=file]")!,
      new File([etrPem], "my.etr"),
    );

    // All our exemption token request data should be on this overview page...
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
      new File([cert1234Pem], "my.cert"),
    );

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
      new File([priv1234Pem], "my.priv"),
    );
    await user.type(screen.getByPlaceholderText(/Passphrase/), "1234");
    const signButton = screen.getByRole("button", { name: /Sign and/ });
    expect(signButton).toBeEnabled();

    downloadedFile = undefined as any;
    await user.click(signButton);
    await waitFor(() => expect(downloadedFile).toBeTruthy());
    expect(downloadedFile?.filename).toMatch(/Anonymous-....-..-..\.et$/);
    expect(downloadedFile?.mimeType).toMatch("application/x-pem-file");
    const etPem = downloadedFile?.content as Uint8Array;
    expect(new TextDecoder().decode(etPem)).toMatch(
      /-----BEGIN SECUREDNA EXEMPTION TOKEN-----/,
    );
    const et = etBundlePemToJsObject(etPem).V1.data;
    expect(et.request.requestor_auth_devices).toEqual([
      {
        Yubikey: "cccccccccccc",
      },
    ]);

    expect(et.issuer_fields.issuer_auth_devices).toEqual([]);

    await user.click(screen.getByRole("link", { name: /Subset/ }));
    await user.upload(
      document.body.querySelector('input[accept=".et"]')!,
      new File([etPem], "my.et"),
    );
    await user.upload(
      document.body.querySelector('input[accept=".priv"]')!,
      new File([etrPrivateKey], "my.priv"),
    );
    await user.type(screen.getByPlaceholderText(/Passphrase/), "abcdefghij");

    // Remove SARS-CoV-2 but keep the Aflatoxins.
    const cov = screen.getByRole("checkbox", { name: /SARS-CoV/ });
    expect(cov).toBeChecked();
    await user.click(cov);
    const afla = screen.getByRole("checkbox", { name: /Aflatoxins/ });
    expect(afla).toBeChecked();

    const yubikeyButton = screen.getByRole("button", { name: /Add Yubikey/ });
    await user.click(yubikeyButton);
    const yubikeyOtp = screen.getByPlaceholderText(/Yubikey OTP/);
    await user.type(yubikeyOtp, "e".repeat(44));
    const addButton = screen.getByRole("button", { name: /^Add Yubikey$/ });
    await user.click(addButton);

    const dlButton = screen.getByRole("button", { name: /Download subset/ });
    expect(dlButton).toBeEnabled();

    downloadedFile = undefined as any;
    await user.click(dlButton);
    await waitFor(() => expect(downloadedFile).toBeTruthy());
    expect(downloadedFile?.filename).toMatch(/Anonymous-....-..-..-sub\.et$/);
    expect(downloadedFile?.mimeType).toMatch("application/x-pem-file");
    const subEtPem = downloadedFile?.content as Uint8Array;
    const subEt = etBundlePemToJsObject(subEtPem).V1.data;
    expect(subEt.request.exemptions.map((x) => x.name)).toEqual(["Aflatoxins"]);
    expect(subEt.request.requestor_auth_devices).toEqual([
      {
        Yubikey: "eeeeeeeeeeee",
      },
    ]);
    expect(subEt.issuer_fields.issuer_auth_devices).toEqual([]);
  });
});
