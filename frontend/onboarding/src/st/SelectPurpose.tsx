/**
 * Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { UseFormRegister } from "react-hook-form";
import { Card } from "../Card";
import type { FormValues } from "./submit";

export function SelectPurpose(props: {
  register: UseFormRegister<FormValues>;
  name: keyof FormValues;
}) {
  return (
    <fieldset>
      <legend className="my-4">Select the purpose of your token:</legend>
      <Card>
        <div>
          <input
            type="radio"
            className="h-4 w-4 align-middle"
            value="centralized"
            id="centralized"
            {...props.register(props.name)}
          />
          <label className="ml-2" htmlFor="centralized">
            I am a centralized provider making a single token for all my
            screening.
          </label>
        </div>
        <div>
          <input
            type="radio"
            className="h-4 w-4 align-middle"
            value="benchtop"
            id="benchtop"
            {...props.register(props.name)}
          />
          <label className="ml-2" htmlFor="benchtop">
            I am making a token for a single hardware synthesizer.
          </label>
        </div>
        <div>
          <input
            type="radio"
            className="h-4 w-4 align-middle"
            value="screening"
            id="screening"
            {...props.register(props.name)}
          />
          <label className="ml-2" htmlFor="screening">
            I am a BSA making a token for screening exemption token requests.
          </label>
        </div>
      </Card>
    </fieldset>
  );
}
