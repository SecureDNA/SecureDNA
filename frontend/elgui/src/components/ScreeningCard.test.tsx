/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { ApiResponse } from "@securedna/frontend_common";
import type { ScreeningProgress } from "src/screening/screening";
import type { ScreeningWorkerParams } from "src/screening/types";
import { beforeEach, describe, expect, test, vi } from "vitest";

// Patch in crypto.subtle for the Node test environment
const crypto = require("node:crypto");
Object.defineProperty(globalThis, "crypto", {
  value: {
    subtle: crypto.webcrypto.subtle,
  },
});

// Mock the screening module
vi.mock("src/screening/screening", () => ({
  performScreening: vi.fn(),
}));

describe("cachedScreening concurrency limiting", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.clearAllMocks();
  });

  test("limits concurrent screenings to maximum of 10", async () => {
    // Import after mocks are set up
    const { cachedScreening } = await import("./ScreeningCard");
    const { performScreening } = await import("src/screening/screening");

    // Track concurrent executions
    let currentlyActive = 0;
    let maxObservedConcurrent = 0;
    const resolvers: Array<() => void> = [];

    // Mock performScreening to block until we manually resolve
    vi.mocked(performScreening).mockImplementation(
      async (
        _params: ScreeningWorkerParams,
        callback: (progress: ScreeningProgress) => void,
      ) => {
        currentlyActive++;
        maxObservedConcurrent = Math.max(
          maxObservedConcurrent,
          currentlyActive,
        );

        // Block until manually resolved
        await new Promise<void>((resolve) => {
          resolvers.push(resolve);
        });

        // Simulate successful completion
        const result: ApiResponse = {
          synthesis_permission: "granted",
          hits_by_record: [],
        };
        callback({ done: true, result });

        currentlyActive--;
      },
    );

    // Start 15 concurrent screening requests (more than the limit of 10)
    const numRequests = 15;
    const screeningPromises: Array<Promise<void>> = [];

    for (let i = 0; i < numRequests; i++) {
      const params: ScreeningWorkerParams = {
        sequence: `>test_${i}\nACGT`,
      } as any;
      const promise = cachedScreening(params, () => {});

      screeningPromises.push(promise);
    }

    // Wait a bit for the concurrent requests to start
    await new Promise((resolve) => setTimeout(resolve, 50));

    // At this point, exactly 10 should be active (the max)
    expect(currentlyActive).toBe(10);
    expect(maxObservedConcurrent).toBe(10);

    // Resolve 5 requests
    for (let i = 0; i < 5; i++) {
      resolvers[i]();
    }
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Now 5 more should have started (still at 10 active)
    expect(currentlyActive).toBe(10);
    expect(maxObservedConcurrent).toBe(10);

    // Resolve all remaining requests
    for (let i = 5; i < resolvers.length; i++) {
      resolvers[i]();
    }
    await Promise.all(screeningPromises);

    // All should be complete
    expect(currentlyActive).toBe(0);
    expect(performScreening).toHaveBeenCalledTimes(numRequests);
    expect(maxObservedConcurrent).toBe(10); // Never exceeded 10
  });
});
