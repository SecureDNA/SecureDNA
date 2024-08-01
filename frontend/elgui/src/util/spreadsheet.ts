/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import * as wasm from "quickdna_wasm";
import type {
  FastaFile,
  OrganismWithSource,
  SequenceIdentifierWithSource,
} from "src/types";
import * as XLSX from "xlsx";

function fastaFileIsEmpty(fastaFile: FastaFile): boolean {
  return fastaFile.records.every((r) => r.contents.trim() === "");
}

function andList(strings: string[]): string {
  const n = strings.length;
  if (n < 2) {
    return strings.join("");
  }
  return `${strings.slice(0, n - 1).join(", ")} and ${strings[n - 1]}`;
}

const maxErrors = 10;

function parseFromWorksheet(
  worksheet: XLSX.WorkSheet,
): Map<string, SequenceIdentifierWithSource[]> {
  const range = XLSX.utils.decode_range(worksheet["!ref"]!);

  // Look for columns that are entirely parseable as FASTA cells.
  // If that fails, return errors for the column with the fewest errors (the "best" column).
  const fastaColumnNames: string[] = [];
  let organismsColumn: Map<string, SequenceIdentifierWithSource[]> | undefined =
    undefined;
  let bestColumnName: string | undefined = undefined;
  let bestErrors: string[] | undefined = undefined;

  for (let col = range.s.c; col <= range.e.c; col++) {
    const organisms: Map<string, SequenceIdentifierWithSource[]> = new Map();
    const errors: string[] = [];
    for (let row = range.s.r; row <= range.e.r; row++) {
      const cellAddress = XLSX.utils.encode_cell({ r: row, c: col });
      const cellValue = String(worksheet[cellAddress]?.v ?? "");
      if (!cellValue) continue;
      const result = wasm.parse_fasta(cellValue);
      if (typeof result === "string") {
        // Ignore errors in what's probably a header row.
        if (row > 0 && errors.length < maxErrors) {
          errors.push(`In cell ${cellAddress}: FASTA parse error: ${result}`);
        }
        continue;
      }
      const data = result as FastaFile;
      if (fastaFileIsEmpty(data)) {
        if (errors.length < maxErrors) {
          errors.push(
            `In cell ${cellAddress}: Empty FASTA record. (FASTA cannot be spread across cells.)`,
          );
        }
        continue;
      }
      const nameCol = col === 0 ? 1 : 0;
      const nameAddress = XLSX.utils.encode_cell({ r: row, c: nameCol });
      const name = String(worksheet[nameAddress]?.v ?? "");
      if (!organisms.has(name)) {
        organisms.set(name, []);
      }
      organisms.get(name)?.push({ Dna: data, source: cellValue });
    }

    if (organisms.size === 0) continue;

    const columnName = XLSX.utils.encode_col(col);
    if (errors.length === 0) {
      fastaColumnNames.push(columnName);
      organismsColumn = organisms;
    } else if (bestErrors === undefined || errors.length < bestErrors.length) {
      bestColumnName = columnName;
      bestErrors = errors;
    }
  }

  if (!organismsColumn) {
    if (bestErrors === undefined) {
      throw new Error(
        "The spreadsheet does not seem to contain a column of FASTA data.",
      );
    }
    throw new Error(
      `Your spreadsheet looks like column ${bestColumnName} contains FASTA data, but it could not be parsed completely:\n- ${bestErrors.join("\n- ")}`,
    );
  }
  if (fastaColumnNames.length > 1) {
    const all = fastaColumnNames.length === 2 ? "both" : "all";
    const cols = andList(fastaColumnNames);
    throw new Error(
      `Columns ${cols} ${all} contain FASTA data. Please reformat or split up the spreadsheet.`,
    );
  }

  return organismsColumn;
}

export function parseExemptionsFromSpreadsheetData(
  data: Uint8Array,
): OrganismWithSource[] {
  const workbook = XLSX.read(data, { type: "array" });
  if (workbook.SheetNames.length === 0) {
    throw new Error("The file could not be parsed as a spreadsheet.");
  }
  const organisms: Map<string, SequenceIdentifierWithSource[]> = new Map();
  for (const sheetName of workbook.SheetNames) {
    try {
      const sheet = workbook.Sheets[sheetName];
      for (const [name, sequences] of parseFromWorksheet(sheet)) {
        if (!organisms.has(name)) {
          organisms.set(name, []);
        }
        organisms.get(name)?.push(...sequences);
      }
    } catch (e) {
      // If there are multiple worksheets, prepend the sheet name to the error
      // message for clarification.
      if (workbook.SheetNames.length > 1) {
        throw new Error(`${sheetName}: ${(e as Error).message}`);
      }
      throw e;
    }
  }
  return [...organisms].map(([name, sequences]) => ({ name, sequences }));
}
