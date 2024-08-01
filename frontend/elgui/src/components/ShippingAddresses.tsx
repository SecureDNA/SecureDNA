/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { FieldArrayRenderProps } from "formik";
import { enCountryNames } from "src/data/countries";
import { type ShippingAddress, emptyShippingAddress } from "src/types";

import { Button } from "./Button";
import { FormInput, FormSelect, FormTextArea } from "./FormInput";
import { RemoveButton } from "./RemoveButton";

export interface ShippingAddressesProps {
  /// From Formik's FieldArray `render`: https://formik.org/docs/api/fieldarray
  arrayHelpers: FieldArrayRenderProps;
  /// The array managed by the FieldArray.
  shippingAddresses: ShippingAddress[];
}

/// Editable table component, to be used in the `render` method of a Formik
/// FieldArray. https://formik.org/docs/api/fieldarray
export const ShippingAddresses = (props: ShippingAddressesProps) => {
  const { arrayHelpers, shippingAddresses } = props;
  return (
    <>
      <div className="my-4">
        {shippingAddresses.map((address, index) => (
          <div
            key={address.id}
            className={
              shippingAddresses.length > 0
                ? "first:rounded-t-xl last:rounded-b-xl bg-primary/10 p-5 border border-primary"
                : ""
            }
          >
            {
              <div className="flex flex-row space-x-4">
                <h3 className="text-lg font-bold ml-1 mr-auto">
                  Address #{index + 1}
                </h3>
                <RemoveButton
                  className="disabled:opacity-20 h-6 w-6"
                  disabled={shippingAddresses.length <= 1}
                  onClick={() => {
                    if (shippingAddresses.length > 1) {
                      arrayHelpers.remove(index);
                    }
                  }}
                />
              </div>
            }
            <div className="flex flex-row space-x-2">
              <FormSelect
                required={true}
                label="Country"
                name={`shippingAddresses.${index}.country`}
              >
                <option disabled value="" />
                {enCountryNames.map(([code, name]) => (
                  <option key={code} value={code}>
                    {name as string}
                  </option>
                ))}
              </FormSelect>
              <FormInput
                label="State / Province"
                name={`shippingAddresses.${index}.state`}
              />
            </div>
            <div className="flex flex-row space-x-2">
              <FormInput
                label="City"
                name={`shippingAddresses.${index}.city`}
              />
              <FormInput
                label="Postal code"
                name={`shippingAddresses.${index}.postalCode`}
              />
            </div>
            <FormTextArea
              type="text"
              rows={2}
              label="Street address"
              required={true}
              name={`shippingAddresses.${index}.streetAddress`}
            />
            <FormInput
              label="Institution / Organization"
              name={`shippingAddresses.${index}.institution`}
            />
          </div>
        ))}
      </div>
      <Button
        className="self-center"
        type="button"
        onClick={() => arrayHelpers.push(emptyShippingAddress())}
      >
        + Add another shipping address
      </Button>
    </>
  );
};
