/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { Field, FieldProps, useFormikContext } from "formik";
import * as wasm from "quickdna_wasm";
import { useRef, useState } from "react";
import { toast } from "react-hot-toast";
import { FastaFile } from "src/types";

import { Button } from "./Button";
import { FormTextArea } from "./FormInput";
import { LinkButton } from "./LinkButton";
import { PrimaryButton } from "./PrimaryButton";
import { RemoveButton } from "./RemoveButton";

export interface FastaFieldProps {
  source: string;
  data: FastaFile;
  setter: (source: string, data: FastaFile) => void;
  showAsLinksIfEmpty?: boolean;
}

export interface FastaModalProps {
  setter: (source: string, data: FastaFile) => void;
  hide: () => void;
}

const FastaModal = (props: FastaModalProps) => {
  return (
    <div className="relative max-h-screen overflow-y-auto max-w-4xl p-6 rounded-xl shadow-xl mx-auto z-30 bg-gray-200 my-auto flex-1">
      <h2>Editing FASTA exemption</h2>
      <RemoveButton
        title="Close without saving"
        className="absolute top-4 right-4"
        onClick={props.hide}
      />
      <Field name="fastaEditor">
        {({
          field, // { name, value, onChange, onBlur }
          form,
          meta,
        }: FieldProps) => (
          <div className="flex flex-col space-y-4">
            <FormTextArea
              label="Source"
              monospace={true}
              {...field}
              placeholder={">Example\nACGTACGT"}
            />
            <PrimaryButton
              type="button"
              onClick={function (): void | Promise<any> {
                const result = wasm.parse_fasta(field.value);
                if (typeof result === "string") {
                  form.setErrors({ fastaEditor: result });
                  return;
                }
                if (!result) {
                  form.setErrors({ fastaEditor: "An unknown error occurred." });
                  return;
                }
                props.setter(field.value, result as FastaFile);
                props.hide();
              }}
            >
              Save
            </PrimaryButton>
          </div>
        )}
      </Field>
    </div>
  );
};

/**
 * Returns a human-readable rich-text string describing the records field of a
 * FastaFile. For example, `my_seq and 3 others (1,234 bp)`.
 */
export function describeRecords(records: FastaFile["records"]): JSX.Element {
  if (!records.length) {
    return <>None</>;
  }
  const bp = records.reduce((a, r) => a + r.contents.length, 0);
  let firstHeader = records[0]?.header?.trim() || "";
  if (firstHeader.length > 30) {
    firstHeader = firstHeader.slice(0, 30) + "…";
  }
  const n = records.length;
  let summary: JSX.Element;
  if (n === 1) {
    summary = firstHeader ? <b>{firstHeader}</b> : <>1 entry</>;
  } else {
    summary = firstHeader ? (
      <>
        <b>{firstHeader}</b> and {n - 1} {n === 2 ? "other" : "others"}
      </>
    ) : (
      <>{n} entries</>
    );
  }
  return (
    <>
      {summary} ({bp.toLocaleString("en-US")} bp)
    </>
  );
}

/**
 * An input field into which the user can upload or paste a FASTA file.
 */
export const FastaField = (props: FastaFieldProps) => {
  const [editorVisible, setEditorVisible] = useState(false);
  const description = describeRecords(props.data.records);

  const fileRef = useRef<HTMLInputElement>(null);
  function onFilePicked(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.currentTarget.files;
    if (!files || files.length === 0) {
      toast.error("No file was selected.");
      return;
    }
    if (files.length > 1) {
      toast.error("Multiple file upload is not allowed.");
      return;
    }
    const file = files[0];
    const reader = new FileReader();
    reader.onerror = () => {
      toast.error(`File ${file.name} could not be read.`);
    };
    reader.onload = (loaded) => {
      const fasta = loaded.target?.result as string;
      const result = wasm.parse_fasta(fasta);
      if (fileRef.current) {
        fileRef.current.value = "";
        fileRef.current.files = null;
      }
      if (typeof result === "string") {
        toast.error(result);
        return;
      }
      props.setter(fasta, result);
    };
    reader.readAsText(file);
  }

  const formik = useFormikContext<{ fastaEditor: string }>();

  return (
    <div className={"flex flex-row items-center"}>
      <input
        accept=".fasta,.fa,.fna,.ffn,.frn"
        type="file"
        className="hidden"
        ref={fileRef}
        onChange={onFilePicked}
      />
      {props.showAsLinksIfEmpty && props.source.length === 0 ? (
        <div className="text-sm w-full text-end">
          <LinkButton
            type="button"
            onClick={() => {
              formik.setFieldValue("fastaEditor", props.source);
              setEditorVisible(true);
            }}
          >
            Add FASTA
          </LinkButton>{" "}
          or{" "}
          <LinkButton type="button" onClick={() => fileRef.current?.click()}>
            upload FASTA
          </LinkButton>
        </div>
      ) : (
        <div className="flex flex-row">
          <div className="flex-1 text-center bg-black/5 px-2 py-2 rounded">
            {description}
          </div>
          <div className="flex ml-2">
            <Button
              className="py-2 rounded-r-none"
              type="button"
              onClick={() => {
                formik.setFieldValue("fastaEditor", props.source);
                setEditorVisible(true);
              }}
            >
              Edit
            </Button>
            <Button
              className="py-2 rounded-l-none enabled:border-l-0"
              type="button"
              onClick={() => fileRef.current?.click()}
            >
              Upload
            </Button>
          </div>
        </div>
      )}
      {editorVisible && (
        <div className="fixed inset-0 bg-opacity-50 transition-opacity bg-black z-20 flex">
          <FastaModal
            setter={props.setter}
            hide={() => setEditorVisible(false)}
          />
        </div>
      )}
    </div>
  );
};
