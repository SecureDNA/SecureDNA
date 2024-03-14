/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import React from "react";
import { useRef, useState } from "react";
import Popup from "reactjs-popup";
import { copyToClipboard, ncbi } from "../..";
import { FastaRecordHits, HazardHits, HitRegion } from "../..";
import { HitVisualization, organismHue } from "./HitVisualization";

export interface GroupVisualizationProps {
  index: number;
  group: FastaRecordHits;
  compact?: boolean;
}

function wrap(seq: string, width: number): string {
  let lines = [];
  for (let i = 0; i < seq.length; i += width) {
    lines.push(seq.slice(i, i + width));
  }
  return lines.join("\n");
}

function hitTypeName(type: "nuc" | "aa"): string {
  return type === "aa" ? "AA" : "DNA";
}

function copyHitsToClipboard(
  header: string,
  type: "nuc" | "aa",
  hitRegions: HitRegion[],
  organismName: string
) {
  const title = header.replace(/\r?\n.*/ms, "");
  const fasta = hitRegions
    .map(
      (region) =>
        `>Hit for ${organismName} at position ${region.seq_range_start} in "${title}"\n` +
        `${wrap(region.seq, 60)}\n`
    )
    .join("\n");
  copyToClipboard(hitTypeName(type) + " hits for " + organismName, fasta);
}

export interface OrganismNameProps {
  name: string;
  index: number;
  group: FastaRecordHits;
  setHovered: (hovered: string) => void;
}

export const OrganismName = (props: OrganismNameProps) => {
  const { name, index, group, setHovered } = props;
  const ref = useRef(null);
  let hits: { nuc: HitRegion[]; aa: HitRegion[] } = { nuc: [], aa: [] };
  for (const region of group.hits_by_hazard) {
    if (region.most_likely_organism.name === name) {
      hits[region.type].push(...region.hit_regions);
    }
  }
  hits.nuc.sort();
  hits.aa.sort();

  const hue = organismHue(index);
  return (
    <Popup
      ref={ref}
      trigger={
        <span
          title="Click for options"
          onMouseEnter={setHovered.bind(this, name)}
          onMouseLeave={setHovered.bind(this, "")}
          onFocus={setHovered.bind(this, name)}
          onBlur={setHovered.bind(this, "")}
          className="px-1 font-bold cursor-pointer hover:underline"
          style={{ color: `hsla(${hue}, 60%, 50%, 1)` }}
        >
          {name}
        </span>
      }
    >
      <div className="bg-white flex flex-col p-3 space-y-3 rounded-lg shadow-lg">
        {(["nuc", "aa"] as const).map((type) => (
          <button
            key={type}
            className="text-blue-500 enabled:hover:underline disabled:text-gray-400"
            type="button"
            disabled={hits[type].length === 0}
            onClick={() => {
              copyHitsToClipboard(group.fasta_header, type, hits[type], name);
              (ref.current as any)?.close();
            }}
          >
            {hits[type].length === 0
              ? `(no ${hitTypeName(type)} hits)`
              : `Copy ${hitTypeName(type)} hits as FASTA`}
          </button>
        ))}
      </div>
    </Popup>
  );
};

/// Pick a good increment for notches, e.g. every 200bp if the input is 1234bp.
/// This function picks the first number among 10, 20, 50, 100, 200, 500...
/// that's greater than 10% of the total length.
function notchIncrement(length: number): number {
  const atLeast = length / 10;
  // Round down to nearest power of 10:
  const n = Math.pow(10, Math.floor(Math.log10(atLeast)));
  if (n >= atLeast) return n;
  if (2 * n >= atLeast) return 2 * n;
  if (5 * n >= atLeast) return 5 * n;
  return 10 * n;
}

export const GroupVisualization = (props: GroupVisualizationProps) => {
  const { group, compact } = props;
  const allLikelyOrganisms = [
    ...new Set(group.hits_by_hazard.map((x) => x.most_likely_organism.name)),
  ];
  allLikelyOrganisms.sort();
  const allLikelyANs = [
    ...new Set(group.hits_by_hazard.flatMap((x) => x.most_likely_organism.ans)),
  ];
  allLikelyANs.sort();

  const [hovered, setHovered] = useState("");

  const length = group.sequence_length;
  const increment = notchIncrement(length);
  let indices = [];
  for (let i = 0; i < length; i += increment) {
    indices.push(i);
  }
  indices.push(length);
  let markers = indices.map((i) => {
    const percentage = (i / length) * 100;
    return (
      <div
        key={i}
        style={{
          left: percentage + "%",
          transform: "translate(-50%, -1rem)",
        }}
        className="opacity-50 text-xs text-center absolute inline-block translate"
      >
        {i.toLocaleString()}
      </div>
    );
  });

  return (
    <div className={compact ? "w-full my-4" : "w-[800px] my-4"}>
      <h3 className="text-xl mb-6">
        Hits in record{" "}
        {group.fasta_header.trim() ? (
          <span className="text-primary font-bold">{group.fasta_header}</span>
        ) : (
          ""
        )}{" "}
        on lines {group.line_number_range[0].toString()}&ndash;
        {group.line_number_range[1].toString()}:
      </h3>
      <div
        className={
          compact
            ? "select-none cursor-pointer relative bg-black/5 rounded h-12 w-full mb-2"
            : "select-none cursor-pointer relative bg-black/5 rounded h-16 w-[800px] mb-2"
        }
      >
        {markers}
        {group.hits_by_hazard.flatMap((hit, i) =>
          hit.hit_regions.map((region, j) => (
            <HitVisualization
              key={(i << 16) | j}
              hit={hit}
              region={region}
              hovered={hovered}
              group={group}
              allLikelyOrganisms={allLikelyOrganisms}
            />
          ))
        )}
      </div>
      <div
        className={
          compact
            ? "flex flex-col flex-wrap ml-4 text-sm"
            : "flex flex-wrap items-center ml-8"
        }
      >
        <span className="-ml-4 mr-1">Organisms (click for options): </span>
        {allLikelyOrganisms.map((name, index) => (
          <OrganismName
            key={index}
            name={name}
            index={index}
            group={group}
            setHovered={setHovered}
          />
        ))}
      </div>{" "}
      <div
        className={
          compact
            ? "flex flex-wrap items-center ml-4 text-sm mt-2"
            : "flex flex-wrap items-center ml-8"
        }
      >
        <span className="-ml-4 mr-1">View ANs in GenBank: </span>
        {allLikelyANs.map((an) => (
          <a
            key={an}
            onMouseEnter={setHovered.bind(this, an)}
            onMouseLeave={setHovered.bind(this, "")}
            onFocus={setHovered.bind(this, an)}
            onBlur={setHovered.bind(this, "")}
            className="px-1 text-primary font-bold cursor-pointer hover:underline"
            target="_blank"
            href={ncbi.url(an)}
          >
            {an}
          </a>
        ))}
      </div>
    </div>
  );
};
