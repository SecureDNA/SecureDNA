/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

export const Version = () => {
  const date = import.meta.env.VITE_GIT_COMMIT_DATE as string;
  const ymd = date.substring(0, 10);
  const branch = import.meta.env.VITE_GIT_BRANCH_NAME as string;
  const hash = import.meta.env.VITE_GIT_COMMIT_HASH as string;
  return (
    <div className="">
      {import.meta.env.DEV
        ? `${branch}@${hash.substring(0, 7)} (${ymd})`
        : `version ${ymd}`}
    </div>
  );
};
