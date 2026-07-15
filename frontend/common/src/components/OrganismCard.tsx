/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { useEffect, useState } from "react";
import { type Organism, type SequenceIdentifier, ncbi } from "..";
import { Card } from "./Card";
import { SequenceLink } from "./SequenceLink";

function showName(organism: Organism) {
  if (organism.name) {
    return organism.name;
  }
  if ("Dna" in organism.sequences[0]) {
    return "DNA sequence";
  }
  return "NCBI accession";
}

function elaborate(si: SequenceIdentifier) {
  if ("Id" in si) {
    const [name, setName] = useState("Loading...");
    useEffect(() => {
      ncbi
        .title(si.Id)
        .then((t: string | undefined) => {
          if (t) {
            setName(t);
          } else {
            setName("Unknown accession number");
          }
        })
        .catch(() => {
          setName("Failed to get title");
        });
    }, [si.Id]);
    return <div className="text-xs my-1 ml-4 tracking-wide">{name}</div>;
  }
  return (
    <div className="my-1">
      {si.Dna.records.map((record, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
        <pre key={i} className="text-xs ml-4 whitespace-pre">
          {`>${record.header || "(no header)"}`}
          {"\n"}({record.contents.length} bp sequence)
        </pre>
      ))}
    </div>
  );
}

export const OrganismCard = (props: {
  organism: Organism;
  compact?: boolean;
}) => {
  const { organism, compact } = props;
  return (
    <Card className="flex flex-col" small={props.compact}>
      <h3 className="font-bold text-lg">
        <span>{showName(organism)}</span>{" "}
      </h3>
      {organism.sequences.map(
        (sequence, j) =>
          ("Id" in sequence || sequence.Dna.records.length > 0) && (
            // biome-ignore lint/suspicious/noArrayIndexKey: the array won't change.
            <div className="inline-block mr-2" key={j}>
              <SequenceLink identifier={sequence} />
              {!compact && elaborate(sequence)}
            </div>
          ),
      )}
    </Card>
  );
};
