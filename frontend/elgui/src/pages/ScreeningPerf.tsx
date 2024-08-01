/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { useEffect } from "react";
import {
  type ScreeningProgress,
  performScreening,
} from "src/screening/screening";

function randomSequence(length: number): string {
  let s = "";
  for (let i = 0; i < length; ++i) s += "ACTG"[(Math.random() * 4) | 0];
  return s;
}

/**
 * A test page that measures how long it takes to screen 1, 2, ... 12 sequences
 * of 100 bp each at the same time. The results are logged to the console.
 */
export default function ScreeningPerf() {
  useEffect(() => {
    async function go() {
      for (let n = 1; n <= 12; n++) {
        console.time(`${n}`);
        await new Promise<void>((res) => {
          let count = 0;
          const f = (progress: ScreeningProgress) => {
            if (progress.done) {
              count++;
              if (count === n) {
                console.timeEnd(`${n}`);
                res();
              }
            }
          };
          for (let i = 0; i < n; i++)
            performScreening(
              {
                // sequence: randomSequence(((1000 / n) | 0) + 42),
                sequence: randomSequence(100),
              },
              f,
            );
        });
      }
    }
    go();
  }, []);
  return (
    <div className="max-w-prose mb-8">
      <h1>Screening performance</h1>
    </div>
  );
}
