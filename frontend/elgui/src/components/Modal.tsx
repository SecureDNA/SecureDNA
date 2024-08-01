/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

export const Modal = (props: { close: () => void; children: JSX.Element }) => {
  return (
    <div
      className="fixed inset-0 transition-opacity bg-black/50 z-20 flex"
      onClick={() => props.close()}
      onKeyUp={(e) => {
        if (e.key === "Esc") props.close();
      }}
    >
      <div
        className="relative max-h-screen overflow-y-auto px-6 py-4 rounded-xl shadow-xl mx-auto z-30 bg-white my-auto"
        onClick={(e) => e.stopPropagation()}
        onKeyUp={(e) => {
          if (e.key === "Esc") props.close();
        }}
      >
        {props.children}
      </div>
    </div>
  );
};
