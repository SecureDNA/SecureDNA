/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, test } from "vitest";
import App from "./App";

describe("web interface", () => {
  test("smoke test", async () => {
    const user = userEvent.setup();
    render(<App />);
    expect(user).toBeTruthy();
    await screen.findByText(/Web Interface/i);
  });
});
