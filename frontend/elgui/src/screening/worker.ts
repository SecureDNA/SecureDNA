/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { ApiResponse } from "@securedna/frontend_common";

const enumerate_tier = import.meta.env.DEV ? "staging" : "prod";
const enumerate_apex = "securedna.org";
const doh_provider = "1.1.1.1"; // cloudflare
const use_http = false; // whether to rewrite internal api calls from https:// → http:// (useful for local testing)

export async function initScreen() {
  const screening = await import("screening_wasm/screening_wasm.js");
  await screening.default();

  self.onmessage = async (e) => {
    type SelfWithPorts = typeof self & { $ports?: Record<string, MessagePort> };
    const self_: SelfWithPorts = self;

    const { sequence, requestId } = e.data;
    self_.$ports ??= {};
    self_.$ports[requestId] = e.ports[0];
    // console.time(requestId);
    try {
      const result = await screening.screen(sequence, {
        region: null, // TODO(theia) / TODO(lynn): we should maybe have a settings dropdown or something for this?
        enumeration_settings: {
          tier: enumerate_tier,
          apex: enumerate_apex,
          doh_provider,
        },
        fixed_domains: null,
        include_debug_info: true,
        include_runts: true,
        request_id: requestId,
        use_http,
      });
      // console.log(requestId, result);
      // console.timeEnd(requestId);
      e.ports[0].postMessage({ done: true, result });
    } catch (err) {
      let result: ApiResponse = {
        synthesis_permission: "denied",
        hits_by_record: [],
        warnings: [],
        errors: [{ diagnostic: String(err), additional_info: "" }],
      };
      e.ports[0].postMessage({ done: true, result });
    } finally {
      delete self_.$ports[requestId];
      self.close();
    }
  };
  self.postMessage("ready");
}

initScreen();
