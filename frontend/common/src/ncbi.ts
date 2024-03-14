/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import Bottleneck from "bottleneck";

const limiter = new Bottleneck({ minTime: 350, maxConcurrent: 10 });

const baseUrl = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/";

async function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function fetchRetry(url: string): Promise<Response> {
  for (const backoffMs of [1000, 2000, 2000]) {
    try {
      const response = await limiter.schedule(() => fetch(url));
      if (response.status === 200) {
        return response;
      }
      // Else, retry.
    } catch (e) {
      console.error(e);
      // But we'll retry.
    }
    await sleep(backoffMs);
  }
  // Our last effort -- then give up.
  return fetch(url);
}

function db(accession: string): string {
  return accession.startsWith("GCA") || accession.startsWith("GCF")
    ? "assembly"
    : "nuccore";
}

export function url(accession: string): string {
  return `https://www.ncbi.nlm.nih.gov/${db(accession)}/${accession}/`;
}

// nuccore accessions can be fetched by their AN, but for assemblies
// we have to first search and get a numeric "UID".
async function getUid(accession: string): Promise<string> {
  if (db(accession) === "nuccore") {
    return accession;
  }
  const response = await fetchRetry(
    baseUrl + `esearch.fcgi?db=assembly&term=${accession}[AssemblyAccession]`
  );
  const text = await response.text();
  const doc = new window.DOMParser().parseFromString(text, "text/xml");
  const id = doc.querySelector("Id");
  if (id && id.textContent) {
    return id.textContent;
  } else {
    throw new Error("Assembly not found");
  }
}

export async function summary(accession: string): Promise<Document> {
  const response = await fetchRetry(
    baseUrl +
      `esummary.fcgi?db=${db(accession)}&id=` +
      window.encodeURIComponent(await getUid(accession))
  );
  const text = await response.text();
  return new window.DOMParser().parseFromString(text, "text/xml");
}

const lengthCache: Map<string, number | undefined> = new Map();
export async function length(accession: string): Promise<number | undefined> {
  if (lengthCache.has(accession)) {
    return lengthCache.get(accession);
  }
  const doc = await summary(accession);
  const lengthText = doc.querySelector("Item[Name=Length]")?.textContent;
  const length = lengthText ? Number(lengthText) : undefined;

  lengthCache.set(accession, length);
  return length;
}

const fastaCache: Map<string, string> = new Map();
export async function downloadFasta(
  accession: string
): Promise<string | undefined> {
  if (fastaCache.has(accession)) {
    return fastaCache.get(accession);
  }
  const response = await fetchRetry(
    baseUrl +
      `efetch.fcgi?db=${db(accession)}&rettype=fasta&id=` +
      window.encodeURIComponent(await getUid(accession))
  );
  if (response.status === 200) {
    const text = await response.text();
    fastaCache.set(accession, text);
    return text;
  } else {
    return undefined;
  }
}

export async function title(accession: string): Promise<string | undefined> {
  const key = "ncbi-title-" + accession;
  const cached = localStorage.getItem(key);
  if (cached) {
    return cached;
  }
  const doc = await summary(accession);
  const result =
    doc.querySelector("Item[Name=Title]")?.textContent ??
    doc.querySelector("SpeciesName")?.textContent ??
    undefined;
  if (result) {
    localStorage.setItem(key, result);
  }
  return result;
}
