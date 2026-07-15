/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";
import App from "./App";

import fs from "node:fs";
import path from "node:path";

// Patch in crypto.subtle for the Node test environment.
const crypto = require("node:crypto");
Object.defineProperty(globalThis.crypto, "subtle", {
  value: crypto.webcrypto.subtle,
});

const mfCert = fs.readFileSync(
  path.resolve(__dirname, "../../../../test/certs/manufacturer-leaf.cert"),
  { encoding: "utf-8" },
);

const mfPriv = fs.readFileSync(
  path.resolve(__dirname, "../../../../test/certs/manufacturer-leaf.priv"),
  { encoding: "utf-8" },
);

const mfPassphrase = "test";

describe("Synth token onboarding", () => {
  let downloadedFile:
    | {
        content: Uint8Array | string | Blob;
        mimeType: string;
        filename: string;
      }
    | undefined;

  beforeEach(() => {
    const ResizeObserverMock = vi.fn(() => ({
      observe: vi.fn(),
      unobserve: vi.fn(),
      disconnect: vi.fn(),
    }));
    vi.stubGlobal("ResizeObserver", ResizeObserverMock);
    vi.spyOn(global, "scrollTo").mockImplementation(() => {});
  });

  test("end-to-end test", { timeout: 20_000 }, async () => {
    const user = userEvent.setup();
    const app = render(<App />);

    await user.upload(
      document.body.querySelector('input[type=file][accept=".cert"]')!,
      new File([mfCert], "mf.manufacturer.cert"),
    );
    await user.upload(
      document.body.querySelector('input[type=file][accept=".priv"]')!,
      new File([mfPriv], "mf.priv"),
    );
    const passphrase = screen.getByLabelText(
      /manufacturer certificate passphrase/i,
    );
    await user.type(passphrase, "wrong[Tab]");
    await screen.findByText(/passphrase is incorrect/i);
    await user.clear(passphrase);
    await user.type(passphrase, "test[Tab]");
    await screen.findByText(/passphrase correct/i);

    await user.type(screen.getByLabelText(/domain/i), "example.org");
    await user.type(screen.getByLabelText(/rate limit/i), "123");
    await user.type(screen.getByLabelText(/^new pass/i), "hello");
    await user.type(screen.getByLabelText(/^confirm new pass/i), "hello");
    let generate = screen.getByRole("button", { name: /generate/i });
    await user.click(generate);
    await screen.findByText(
      /New token passphrase should be at least 10 characters long/i,
    );
    await user.type(screen.getByLabelText(/^new pass/i), "world");
    await user.click(generate);
    await screen.findByText(
      /New token passphrase does not match its confirmation/i,
    );
    await user.type(screen.getByLabelText(/^confirm new pass/i), "world");

    // Test audit email settings
    {
      await user.click(
        screen.getByRole("checkbox", { name: /Send audit emails/i }),
      );
      await user.type(screen.getByLabelText(/^audit email/i), "a@b.com");

      // As-is, it should complain about not having entered a passphrase yet.
      await user.click(generate);
      await screen.findByText(/Enter a passphrase for a new audit keypair/i);

      expect(
        screen.getByRole("radio", { name: /Inherit key from/i }),
      ).toBeDisabled();

      // If we put in bad passphrases for the audit key it should complain.
      await user.click(screen.getByRole("radio", { name: /New audit key/i }));
      const newAuditKey = screen.getByLabelText(/^To generate a new key and/i);
      const confirmAuditKey = screen.getByLabelText(/^And confirm it/i);

      // Test minimum length:
      await user.type(newAuditKey, "secret");
      await user.type(confirmAuditKey, "secret");
      await user.click(generate);
      await screen.findByText(/New audit passphrase should be at least/i);

      // Test confirmation:
      await user.type(newAuditKey, "secretsecret");
      await user.click(generate);
      await screen.findByText(/New audit passphrase does not match/i);

      // Finally, put in a proper passphrase and confirmation.
      await user.type(confirmAuditKey, "secretsecret");
    }

    await user.click(generate);
    await screen.findByText(/You will provide this file/i);

    const tokenStLink = screen.getByRole("link", { name: /token\.st/i });
    const tokenStDataUrl = tokenStLink.attributes.getNamedItem("href")!.value;
    expect(tokenStDataUrl).toMatch(
      /^data:application\/x-pem-file.*SYNTHESIZER%20TOKEN/,
    );
    const tokenStData = decodeURIComponent(
      tokenStDataUrl.split(";charset=utf-8,")[1],
    );

    const tokenPrivLink = screen.getByRole("link", { name: /token\.priv/i });
    const tokenPrivDataUrl =
      tokenPrivLink.attributes.getNamedItem("href")!.value;
    expect(tokenPrivDataUrl).toMatch(
      /^data:application\/x-pem-file.*ENCRYPTED%20PRIVATE%20KEY/,
    );

    const tokenAuditPrivLink = screen.getByRole("link", {
      name: /token-audit\.priv/i,
    });
    const tokenAuditPrivDataUrl =
      tokenAuditPrivLink.attributes.getNamedItem("href")!.value;
    expect(tokenAuditPrivDataUrl).toMatch(
      /^data:application\/x-pem-file.*ENCRYPTED%20AUDIT%20PRIVATE%20KEY/,
    );

    // Start anew and test inheriting from this synth token:
    app.unmount();
    render(<App />);

    await user.upload(
      document.body.querySelector('input[type=file][accept=".cert"]')!,
      new File([mfCert], "mf.manufacturer.cert"),
    );
    await user.upload(
      document.body.querySelector('input[type=file][accept=".priv"]')!,
      new File([mfPriv], "mf.priv"),
    );
    const passphrase2 = screen.getByLabelText(
      /manufacturer certificate passphrase/i,
    );
    await user.clear(passphrase2);
    await user.type(passphrase2, "test[Tab]");
    await screen.findByText(/passphrase correct/i);

    await user.upload(
      document.body.querySelector('input[type=file][accept=".st"]')!,
      new File([tokenStData], "existing.st"),
    );

    // Config is inherited from the old synth token:
    expect(screen.getByLabelText(/domain/i)).toHaveValue("example.org");
    expect(screen.getByLabelText(/rate limit/i)).toHaveValue(123);

    await user.type(screen.getByLabelText(/^new pass/i), "anothersecret");
    await user.type(
      screen.getByLabelText(/^confirm new pass/i),
      "anothersecret",
    );

    // We can now inherit the audit email key:
    await user.click(
      screen.getByRole("checkbox", { name: /Send audit emails/i }),
    );

    const inheritOption = screen.getByRole("radio", {
      name: /Inherit key from/i,
    });
    expect(inheritOption).toBeEnabled();
    await user.click(inheritOption);

    generate = screen.getByRole("button", { name: /generate/i });
    await user.click(generate);
    await screen.findByText(/You will provide this file/i);

    const tokenStLink2 = screen.getByRole("link", { name: /token\.st/i });
    const tokenStDataUrl2 = tokenStLink2.attributes.getNamedItem("href")!.value;
    expect(tokenStDataUrl2).toMatch(
      /^data:application\/x-pem-file.*SYNTHESIZER%20TOKEN/,
    );
  });
});
