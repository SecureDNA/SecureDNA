/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import {
  Combobox,
  ComboboxInput,
  ComboboxOption,
  ComboboxOptions,
} from "@headlessui/react";
import Fuse from "fuse.js";
import { useState } from "react";

export interface TypeaheadProps {
  id?: string;
  className: string;
  suggestions: string[];
  value: string;
  /// If present, allow typing a custom value with a typeahead label like
  /// `Custom ${custom} "${value}"`.
  custom?: string;
  onChange: (suggestion: string | null) => void;
  limit?: number;
}

export const Typeahead = (props: TypeaheadProps) => {
  const [query, setQuery] = useState("");
  const options = { limit: props.limit ?? 7 };
  const best = new Fuse(props.suggestions).search(query, options);
  const optionClassName = ({ active }: { active: boolean }) =>
    `relative cursor-default select-none py-1 px-4 ${
      active ? "bg-blue-600 text-white" : "text-gray-900"
    }`;

  return (
    <div className="relative">
      <Combobox
        value={props.value}
        onChange={(suggestion) => {
          props.onChange(suggestion);
        }}
      >
        <ComboboxInput
          id={props.id}
          className={props.className}
          onChange={(event) => setQuery(event.target.value)}
        />
        <ComboboxOptions className="z-10 absolute mt-1 max-h-60 w-full overflow-auto rounded-md bg-white py-1 shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-hidden sm:text-sm">
          {best.map(({ item }) => (
            <ComboboxOption className={optionClassName} key={item} value={item}>
              {item}
            </ComboboxOption>
          ))}
          {query.length > 0 && props.custom && (
            <ComboboxOption className={optionClassName} value={query}>
              Custom {props.custom} "{query}"
            </ComboboxOption>
          )}
        </ComboboxOptions>
      </Combobox>
    </div>
  );
};
