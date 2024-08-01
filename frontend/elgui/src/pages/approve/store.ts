/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type {
  Authenticator,
  ExemptionTokenRequest,
  GenbankId,
  Result,
} from "@securedna/frontend_common";
import type { AuthFileResult } from "src/components";
import { needsScreening } from "src/util/etr";
import { create } from "zustand";

export enum PageNumber {
  Upload = 0,
  Overview = 1,
  Screen = 2,
  Sign = 3,
}

interface ApprovalState {
  etrPem?: Result<Uint8Array, string>;
  certPem?: AuthFileResult;
  additionalAuthenticators: Authenticator[];
  etr?: ExemptionTokenRequest;
  screenedExemptions?: Map<string, Set<GenbankId>>;
  pageIndex: PageNumber;
  direction: number;

  setEtr: (etr: ExemptionTokenRequest | undefined) => void;
  setEtrPem: (etrPem: Result<Uint8Array, string> | undefined) => void;
  setCertPem: (certPem: AuthFileResult | undefined) => void;
  setScreenedExemptions: (
    screenedExemptions: Map<string, Set<GenbankId>> | undefined,
  ) => void;
  setAdditionalAuthenticators: (
    additionalAuthenticators: Authenticator[],
  ) => void;

  back: () => void;
  advance: () => void;
}

export const useApprovalStore = create<ApprovalState>()((set) => ({
  additionalAuthenticators: [],
  pageIndex: 0,
  direction: 1,

  setEtr: (etr) => set({ etr }),
  setEtrPem: (etrPem) => set({ etrPem }),
  setCertPem: (certPem) => set({ certPem }),
  setScreenedExemptions: (screenedExemptions) => set({ screenedExemptions }),
  setAdditionalAuthenticators: (additionalAuthenticators) =>
    set({ additionalAuthenticators }),

  back: () =>
    set((state) => {
      const backUpdate = {
        direction: -1,
        pageIndex: state.pageIndex - 1,
      };

      // Depending on the page we're moveing back from, we might clear some
      // state or skip over the screening step:
      switch (state.pageIndex) {
        case PageNumber.Upload:
          return {};
        case PageNumber.Overview:
          return {
            ...backUpdate,
            etr: undefined,
            etrPem: undefined,
          };
        case PageNumber.Screen:
          return backUpdate;
        case PageNumber.Sign:
          if (state.etr && !needsScreening(state.etr)) {
            return { ...backUpdate, pageIndex: state.pageIndex - 2 };
          }
          return backUpdate;
      }
    }),

  advance: () =>
    set((state) => ({
      direction: 1,
      ...(state.pageIndex + 1 === PageNumber.Screen &&
      state.etr &&
      !needsScreening(state.etr)
        ? { pageIndex: state.pageIndex + 2, screenedExemptions: new Map() }
        : { pageIndex: state.pageIndex + 1 }),
    })),
}));
