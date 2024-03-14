/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import countries from "i18n-iso-countries";

import enLocale from "i18n-iso-countries/langs/en.json";
countries.registerLocale(enLocale);

export const enCountryDict = countries.getNames("en");

// Get a list of country names in English, with the US floated to the top:
const _enCountryNames = Object.entries(enCountryDict);
_enCountryNames.sort(([keyA, nameA], [keyB, nameB]) => {
  const sortA = (keyA === "US" ? "0" : "1") + nameA;
  const sortB = (keyB === "US" ? "0" : "1") + nameB;
  return sortA.localeCompare(sortB, "en", { sensitivity: "base" });
});

export const enCountryNames = _enCountryNames;

import zhLocale from "i18n-iso-countries/langs/zh.json";
countries.registerLocale(zhLocale);

// Get a list of country names in Chinese, with China floated to the top:
const _zhCountryNames = Object.entries(countries.getNames("zh"));
_zhCountryNames.sort(([keyA, nameA], [keyB, nameB]) => {
  const sortA = (keyA === "CN" ? "0" : "1") + nameA;
  const sortB = (keyB === "CN" ? "0" : "1") + nameB;
  return sortA.localeCompare(sortB, "zh", { sensitivity: "base" });
});

export const zhCountryNames = _zhCountryNames;
