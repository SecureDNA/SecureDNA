/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

export const ProgressBar = (props: { percentage: number }) => (
  <div className="flex w-full h-1.5 bg-gray-200 rounded-full overflow-hidden dark:bg-gray-700">
    <div
      className="flex flex-col justify-center overflow-hidden bg-blue-500"
      role="progressbar"
      style={{ width: props.percentage + "%" }}
      aria-valuenow={props.percentage}
      aria-valuemin={0}
      aria-valuemax={100}
    ></div>
  </div>
);
