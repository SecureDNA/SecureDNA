/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { describe, expect, test } from "vitest";
import { Sequence } from "@securedna/frontend_common";
import { OrganismWithSource } from "src/types";
import { TextEncoder } from "util";
import { parseExemptionsFromSpreadsheetData } from "./spreadsheet";

function parseCsv(csv: string): OrganismWithSource[] {
  const buffer = new TextEncoder().encode(csv);
  const organisms = parseExemptionsFromSpreadsheetData(buffer);
  return organisms;
}

function dna(source: string): { Dna: Sequence; source: string } {
  return {
    Dna: {
      records: [
        {
          contents: source,
          header: "",
          line_range: [1, 2],
        },
      ],
    },
    source,
  };
}

describe("spreadsheet parser", () => {
  test("parses a FASTA column in a simple csv", () => {
    const parsed = parseCsv(`name1,AAA,comment
name2,CCC,comment
name3,GGG,another comment`);
    expect(parsed).toEqual([
      { name: "name1", sequences: [dna("AAA")] },
      { name: "name2", sequences: [dna("CCC")] },
      { name: "name3", sequences: [dna("GGG")] },
    ]);
  });

  test("parses a single-column csv file", () => {
    expect(parseCsv(`AAA\nCCC\nGGG`)).toEqual([
      { name: "", sequences: [dna("AAA"), dna("CCC"), dna("GGG")] },
    ]);
  });

  test("fails if there is no FASTA column", () => {
    expect(() =>
      parseCsv(`name1,comment
name2,comment
name3,another comment`)
    ).toThrow(/does not seem to contain a column of FASTA data/);
  });

  test("fails if there are multiple FASTA columns", () => {
    expect(() =>
      parseCsv(`name1,AAA,CCC,comment
name2,GGG,TTT,comment
name3,ACG,CGT,another comment`)
    ).toThrow(/Columns.* contain FASTA data/);
  });

  test("allows for a header row", () => {
    expect(
      parseCsv(`Name,FASTA,Comment
name1,AAACAT,comment
name2,GGG,comment
name3,ACG,another comment`)
    ).toEqual([
      { name: "name1", sequences: [dna("AAACAT")] },
      { name: "name2", sequences: [dna("GGG")] },
      { name: "name3", sequences: [dna("ACG")] },
    ]);
  });

  test("doesn't allow for multiple header rows", () => {
    expect(() =>
      parseCsv(`Name,FASTA,Comment
Name,FASTA,Comment
name1,AAA,comment
name2,GGG,comment
name3,GAGAGA,another comment`)
    ).toThrow(/contains FASTA data, but it could not be parsed completely/);
  });

  test("ignores empty cells", () => {
    expect(
      parseCsv(`Name,FASTA,Comment
name1,AAA,comment
name2,,comment
name3,ACGACGA,
,,`)
    ).toEqual([
      { name: "name1", sequences: [dna("AAA")] },
      { name: "name3", sequences: [dna("ACGACGA")] },
    ]);
  });

  test("uses the first non-FASTA column as names", () => {
    expect(
      parseCsv(`Name,Id,FASTA,Comment
name1,19191,AAA,comment
name2,19192,ACGACGA,blah`)
    ).toEqual([
      { name: "name1", sequences: [dna("AAA")] },
      { name: "name2", sequences: [dna("ACGACGA")] },
    ]);
    expect(
      parseCsv(`name1,19191,AAA,comment
name2,19192,ACGACGA,blah`)
    ).toEqual([
      { name: "name1", sequences: [dna("AAA")] },
      { name: "name2", sequences: [dna("ACGACGA")] },
    ]);
    expect(
      parseCsv(`AAA,name1,comment
ACGACGA,name2,blah`)
    ).toEqual([
      { name: "name1", sequences: [dna("AAA")] },
      { name: "name2", sequences: [dna("ACGACGA")] },
    ]);
  });
});
