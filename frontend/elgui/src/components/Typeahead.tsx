/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { Combobox } from "@headlessui/react";
import { useState } from "react";
import Fuse from "fuse.js";

export interface TypeaheadProps {
  className: string;
  suggestions: string[];
  value: string;
  onChange: (suggestion: string) => void;
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
        <Combobox.Input
          className={props.className}
          onChange={(event) => setQuery(event.target.value)}
        />
        <Combobox.Options className="z-10 absolute mt-1 max-h-60 w-full overflow-auto rounded-md bg-white py-1 shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none sm:text-sm">
          {best.map(({ item }) => (
            <Combobox.Option
              className={optionClassName}
              key={item}
              value={item}
            >
              {item}
            </Combobox.Option>
          ))}
          {query.length > 0 && (
            <Combobox.Option className={optionClassName} value={query}>
              Custom organism "{query}"
            </Combobox.Option>
          )}
        </Combobox.Options>
      </Combobox>
    </div>
  );
};
