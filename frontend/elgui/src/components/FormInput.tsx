/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { FieldHookConfig, useField } from "formik";
import { InputHTMLAttributes, useEffect, useState } from "react";
import ReactPhoneNumberInput from "react-phone-number-input";
import "react-phone-number-input/style.css";
import { DigitPattern, fitToDigitPattern } from "src/util/digitPattern";
import { twMerge } from "tailwind-merge";
import { useDebounce } from "use-debounce";
import { Typeahead } from "./Typeahead";

type BaseInputProps = FieldHookConfig<string> & {
  /// Mark this field as "required" by displaying an asterisk on the label.
  required?: boolean;
  /// A label displayed above this field.
  label: string;
  /// If `true`, hide the label normally displayed above the field.
  hideLabel?: boolean;
  /// Use a monospace font for the field contents.
  monospace?: boolean;
  /// A function called on the current value. The result is shown in a tooltip.
  lookup?: (value: string) => Promise<string | undefined>;
  /// An object describing a digit pattern to shape user input into.
  digitPattern?: DigitPattern;
};

type ParseableInputProps = BaseInputProps & {
  /// A function used to parse the input and store a parsed value.
  /// If the given function throws an error, it is used to invalidate the field.
  parse?: (value: string) => Promise<any>;
  /// A list of suggestions to show while the user is typing.
  suggestions?: string[];
  /// A function to run when the user accepts a suggestion.
  onAcceptSuggestion?: (suggestion: string) => void;
};

type GenericInputProps = ParseableInputProps & {
  /// Set to change the inner field type.
  variant: "input" | "select" | "textarea" | "phone";
};

const GenericInput = (props: GenericInputProps) => {
  const [field, meta, helpers] = useField(props);
  const [rawValue, setRawValue] = useState("");

  let classes = "peer border rounded w-full leading-none";
  classes +=
    meta.touched && meta.error ? " border-red-500" : " border-gray-200";
  if (props.monospace) {
    classes += " font-mono";
  }

  const onChange: React.ChangeEventHandler<any> = async (e) => {
    let value = e.target.value;
    if (props.digitPattern) {
      value = fitToDigitPattern(value, props.digitPattern);
    }
    setRawValue(value);
    if (props.parse) {
      try {
        const parsed = await props.parse(value);
        helpers.setValue(parsed as any);
      } catch (e) {
        helpers.setValue("");
        helpers.setError(String(e));
      }
    } else {
      helpers.setValue(value);
    }
  };

  if (props.variant === "phone") {
    // Use "arbitrary variants" to style the insides of the more complex PhoneNumber input:
    // https://tailwindcss.com/blog/tailwindcss-v3-1#arbitrary-values-but-for-variants
    classes += " [&>.PhoneInputCountry]:px-2";
    classes += " [&>input]:p-2 [&>input]:outline-blue-500 [&>input]:rounded";
  } else {
    classes += " p-2 outline-blue-500";
  }

  const popupOuterStyle =
    "invisible peer-focus:visible transition-[visibility,opacity] opacity-0" +
    "peer-focus:opacity-100 absolute rounded-lg px-3 py-2 bottom-[calc(100%_+_0.5rem)] max-w-prose w-max";
  const popupInnerStyle = "absolute left-4 bottom-[-0.25rem] rotate-45 w-2 h-2";

  const [lookupResult, setLookupResult] = useState("");
  const [debouncedValue, { isPending }] = useDebounce(field.value, 700);
  useEffect(() => {
    if (props.lookup && field.value) {
      setLookupResult("…");
      props.lookup(field.value).then((result) => {
        setLookupResult(result ?? "");
      });
    } else {
      setLookupResult("");
    }
  }, [debouncedValue]);

  return (
    <label
      className={twMerge(`relative flex flex-col flex-1 my-1`, props.className)}
    >
      {props.hideLabel ? undefined : (
        <div className="flex flex-row ml-1">
          <div className="text-gray-500 mr-auto">
            {props.label}
            <span className="text-red-500 font-bold">
              {props.required ? " *" : ""}
            </span>
          </div>
          <div className="text-red-500 self-end text-xs">
            {meta.touched && meta.error ? meta.error : "\xa0"}
          </div>
        </div>
      )}
      {props.variant === "select" ? (
        <select className={classes} {...field} placeholder={props.placeholder}>
          {props.children}
        </select>
      ) : props.variant === "textarea" ? (
        <textarea
          className={classes}
          rows={"rows" in props ? props.rows : 20}
          {...field}
          placeholder={props.placeholder}
          onChange={onChange}
          value={props.parse ? rawValue : field.value}
        >
          {props.children}
        </textarea>
      ) : props.variant === "phone" ? (
        <ReactPhoneNumberInput
          className={classes}
          value={field.value}
          onChange={(e) => {
            helpers.setValue(e ?? "");
          }}
          placeholder={props.placeholder}
        >
          {props.children}
        </ReactPhoneNumberInput>
      ) : props.suggestions ? (
        <Typeahead
          className={classes}
          suggestions={props.suggestions}
          value={field.value}
          onChange={(option) => {
            helpers.setValue(option, true);
            props.onAcceptSuggestion?.(option);
          }}
        />
      ) : (
        <input
          className={classes}
          {...field}
          maxLength={(props as InputHTMLAttributes<any>)?.maxLength}
          placeholder={props.placeholder}
          type={props.type}
          onChange={onChange}
          value={props.parse ? rawValue : field.value}
          onBlur={(e) => {
            props.onBlur?.(e as any);
            field.onBlur(e);
          }}
          onKeyDown={(e) => {
            props.onKeyDown?.(e as any);
          }}
        />
      )}
      {props.hideLabel && meta.touched && meta.error ? (
        <div className={`${popupOuterStyle} bg-red-200 text-red-800`}>
          {meta.error}
          <div className={`${popupInnerStyle} bg-red-200`} />
        </div>
      ) : lookupResult ? (
        <div className={`${popupOuterStyle} bg-blue-200 text-blue-800`}>
          {isPending() ? "…" : lookupResult}
          <div className={`${popupInnerStyle} bg-blue-200`} />
        </div>
      ) : undefined}
    </label>
  );
};

export type FormInputProps = ParseableInputProps;
export const FormInput = (props: FormInputProps) => (
  <GenericInput variant="input" {...props} />
);

export type FormTextAreaProps = ParseableInputProps;
export const FormTextArea = (props: FormTextAreaProps) => (
  <GenericInput variant="textarea" {...props} />
);

export type FormSelectProps = BaseInputProps;
export const FormSelect = (props: FormSelectProps) => (
  <GenericInput variant="select" {...props} />
);

export type FormPhoneInputProps = BaseInputProps;
export const FormPhoneInput = (props: FormPhoneInputProps) => (
  <GenericInput variant="phone" {...props} />
);
