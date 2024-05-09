/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

const baseConfig = {
  content: ["./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}"],
  theme: {
    colors: {
      transparent: "transparent",
      current: "currentColor",
      inherit: "inherit",
      white: "#fff",
    },
    fontFamily: {
      primary: ["DM Sans Variable", "sans-serif"],
    },
    container: {
      center: true,
      padding: {
        DEFAULT: "1rem",
        sm: "2rem",
        lg: "4rem",
        "2xl": "7rem",
      },
    },
    fontSize: {
      "2xs": `${12 / 16}rem`,
      xs: `${14 / 16}rem`,
      sm: `${16.5 / 16}rem`,
      base: `${18 / 16}rem`,
      lg: `${22 / 16}rem`,
      xl: `${27 / 16}rem`,
      "2xl": `${30 / 16}rem`,
      "3xl": `${33 / 16}rem`,
      "4xl": `${39 / 16}rem`,
      "5xl": `${59 / 16}rem`,
    },
    extend: {
      minHeight: {
        hero: "min(calc(100vh - 32rem), 720px)",
        "hero-sm": "min(calc(80vh - 32rem), 640px)",
        footer: "25vh",
      },
      maxWidth: {
        content: "58rem",
      },
      animation: {
        "fade-in": "fadeIn 0.2s ease-in-out",
        "fade-out": "fadeOut 0.2s ease-in-out",
        appear: "appear 0.3s ease-out",
        "slide-down": "slideDown 0.3s ease-out",
        "slide-up": "slideUp 0.3s ease-out",
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
        appear: {
          "0%": { opacity: 0, transform: "translateY(10px) scale(0.95)" },
          "100%": { opacity: 1, transform: "translateY(0)" },
        },
        slideDown: {
          "0%": { opacity: 0, transform: "translateY(-10px)" },
          "100%": { opacity: 1, transform: "translateY(0)" },
        },
        slideUp: {
          "0%": { opacity: 0, transform: "translateY(10px)" },
          "100%": { opacity: 1, transform: "translateY(0)" },
        },
      },
    },
  },
};

/** @type {import('tailwindcss').Config} */
module.exports = {
  ...baseConfig,
  theme: {
    ...baseConfig.theme,
    colors: {
      ...baseConfig.theme.colors,
      primary: {
        light: "#E9F9FF",
        DEFAULT: "#A5CFDF",
      },
      secondary: "#070720",
    },
  },
};
