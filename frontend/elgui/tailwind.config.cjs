/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/** @type {import('tailwindcss').Config} */

const colors = require("tailwindcss/colors");

module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "../common/src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    fontFamily: {
      primary: ["DM Sans Variable", "DM Sans", "sans-serif"],
      mono: [
        "ui-monospace",
        "Cascadia Code",
        "Source Code Pro",
        "Menlo",
        "Consolas",
        "DejaVu Sans Mono",
        "monospace",
      ],
    },
    container: {
      center: true,
      padding: {
        DEFAULT: "1rem",
        sm: "2rem",
        lg: "4rem",
        xl: "8rem",
      },
    },
    extend: {
      colors: {
        transparent: "transparent",
        current: "currentColor",
        inherit: "inherit",
        black: "#000",
        white: "#fff",
        primary: {
          light: "#E9F9FF",
          DEFAULT: "#A5CFDF",
        },
        secondary: "#070720",
        warn: "#ff7000",
      },
      animation: {
        "fade-in": "fadeIn 0.2s ease-in-out",
        "fade-out": "fadeOut 0.2s ease-in-out",
        appear: "appear 0.3s ease-out",
        menu: "menu 0.3s ease-out",
        sublinks: "sublinks 0.3s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: 0 },
          "100%": { opacity: 1 },
        },
        fadeOut: {
          "0%": { opacity: 1 },
          "100%": { opacity: 0 },
        },
      },
    },
  },
  plugins: [],
};
