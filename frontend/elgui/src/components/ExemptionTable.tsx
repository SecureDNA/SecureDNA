/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { FieldArray, type FieldArrayRenderProps } from "formik";
import { AnimatePresence, motion } from "framer-motion";
import { useRef, useState } from "react";
import type { OrganismWithSource } from "src/types";
import { parseExemptionsFromSpreadsheetData } from "src/util/spreadsheet";

import { Button } from "./Button";
import { OrganismForm } from "./OrganismForm";
import { RemoveButton } from "./RemoveButton";

export interface ExemptionTableProps {
  /**
   * From Formik's FieldArray `render`: https://formik.org/docs/api/fieldarray
   */
  arrayHelpers: FieldArrayRenderProps;
  /**
   * The array managed by the FieldArray.
   */
  organisms: OrganismWithSource[];
}

/**
 * Editable table component, to be used in the `render` method of a Formik
 * FieldArray. https://formik.org/docs/api/fieldarray
 */
export const ExemptionTable = (props: ExemptionTableProps) => {
  const { arrayHelpers, organisms } = props;
  const [spreadsheetImportError, setSpreadsheetImportError] = useState("");
  const spreadsheetFileInputRef = useRef<HTMLInputElement>(null);

  function handleSpreadsheetSelect(
    event: React.ChangeEvent<HTMLInputElement>,
  ): void {
    const genericError = "The file could not be loaded.";
    if (!event.target.files) {
      setSpreadsheetImportError(genericError);
      return;
    }
    if (event.target.files.length !== 1) {
      setSpreadsheetImportError("Please select a single file.");
      return;
    }
    const file = event.target.files[0];
    const reader = new FileReader();
    reader.onerror = () => {
      setSpreadsheetImportError(genericError);
      return;
    };
    reader.onload = (e: ProgressEvent<FileReader>) => {
      if (!e.target) {
        setSpreadsheetImportError(genericError);
        return;
      }
      const data = new Uint8Array(e.target.result as ArrayBuffer);
      event.target.value = "";
      setSpreadsheetImportError("");
      try {
        const organisms = parseExemptionsFromSpreadsheetData(data);
        for (const organism of organisms) {
          arrayHelpers.push(organism);
        }
      } catch (e) {
        setSpreadsheetImportError((e as Error).message);
      }
    };
    reader.readAsArrayBuffer(file);
  }

  return (
    <div>
      <AnimatePresence mode="sync">
        {organisms.map((organism, index) => (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, height: 0, overflow: "hidden" }}
            key={(organism as any)?.animationKey ?? index}
          >
            <h2>Organisms</h2>
            <p className="my-4">
              Specify the organisms you are requesting an exemption for.
            </p>
            <div className="border border-secondary rounded-lg p-6 mb-4">
              <h2 className="-mt-2">
                Organism #{index + 1}{" "}
                <RemoveButton
                  className="align-text-bottom disabled:opacity-20 float-right w-6 hover:bg-black/10 rounded-lg"
                  disabled={organisms.length <= 1}
                  onClick={() => {
                    if (organisms.length > 1) {
                      arrayHelpers.remove(index);
                    }
                  }}
                />
              </h2>

              <FieldArray
                name={`organisms.${index}.sequences`}
                render={(arrayHelpers: FieldArrayRenderProps) => (
                  <OrganismForm
                    index={index}
                    arrayHelpers={arrayHelpers}
                    sequences={organism.sequences}
                  />
                )}
              />
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
      <div className="flex space-x-2">
        <Button
          type="button"
          onClick={(e) => {
            arrayHelpers.push({
              name: "",
              sequences: [{ Id: "" }],
              animationKey: Math.random(),
            } as OrganismWithSource);
          }}
        >
          + Add organism
        </Button>
        <Button
          type="button"
          onClick={() => spreadsheetFileInputRef.current?.click()}
        >
          Import spreadsheet
        </Button>
      </div>
      {spreadsheetImportError && (
        <div className="text-red-500 whitespace-pre mt-4">
          {spreadsheetImportError}
        </div>
      )}
      <input
        className="hidden"
        type="file"
        ref={spreadsheetFileInputRef}
        onChange={(e) => handleSpreadsheetSelect(e)}
      />
    </div>
  );
};
