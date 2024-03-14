/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  Authenticator,
  ExemptionListTokenRequest,
  GenbankId,
  Result,
} from "@securedna/frontend_common";
import { AuthFileResult } from "src/components";
import { needsScreening } from "src/util/eltr";
import { create } from "zustand";

export enum PageNumber {
  Upload = 0,
  Overview = 1,
  Screen = 2,
  Sign = 3,
}

interface ApprovalState {
  eltrPem?: Result<Uint8Array, string>;
  certPem?: AuthFileResult;
  apiKey: string;
  additionalAuthenticators: Authenticator[];
  eltr?: ExemptionListTokenRequest;
  screenedExemptions?: Map<string, Set<GenbankId>>;
  pageIndex: PageNumber;
  direction: number;

  setEltr: (eltr: ExemptionListTokenRequest | undefined) => void;
  setEltrPem: (eltrPem: Result<Uint8Array, string> | undefined) => void;
  setCertPem: (certPem: AuthFileResult | undefined) => void;
  setApiKey: (apiKey: string) => void;
  setScreenedExemptions: (
    screenedExemptions: Map<string, Set<GenbankId>> | undefined
  ) => void;
  setAdditionalAuthenticators: (
    additionalAuthenticators: Authenticator[]
  ) => void;

  back: () => void;
  advance: () => void;
}

export const useApprovalStore = create<ApprovalState>()((set) => ({
  apiKey: "",
  additionalAuthenticators: [],
  pageIndex: 0,
  direction: 1,

  setEltr: (eltr) => set({ eltr }),
  setEltrPem: (eltrPem) => set({ eltrPem }),
  setCertPem: (certPem) => set({ certPem }),
  setApiKey: (apiKey) => set({ apiKey }),
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
            eltr: undefined,
            eltrPem: undefined,
          };
        case PageNumber.Screen:
          return backUpdate;
        case PageNumber.Sign:
          if (state.eltr && !needsScreening(state.eltr)) {
            return { ...backUpdate, pageIndex: state.pageIndex - 2 };
          } else {
            return backUpdate;
          }
      }
    }),

  advance: () =>
    set((state) => ({
      direction: 1,
      ...(state.pageIndex + 1 === PageNumber.Screen &&
      state.eltr &&
      !needsScreening(state.eltr)
        ? { pageIndex: state.pageIndex + 2, screenedExemptions: new Map() }
        : { pageIndex: state.pageIndex + 1 }),
    })),
}));
