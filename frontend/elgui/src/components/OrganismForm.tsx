/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { faWarning } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { type Result, type Sequence, ncbi } from "@securedna/frontend_common";
import type { FieldArrayRenderProps } from "formik";
import { useEffect, useState } from "react";
import anMap from "src/data/anmap.json";
import type { SequenceIdentifierWithSource } from "src/types";
import { useDebounce } from "use-debounce";

import { FastaField } from "./FastaField";
import { FormInput } from "./FormInput";
import { LinkButton } from "./LinkButton";
import { RemoveButton } from "./RemoveButton";

export interface OrganismFormProps {
  /// Index into the organism list.
  index: number;
  /// From Formik's FieldArray `render`: https://formik.org/docs/api/fieldarray
  arrayHelpers: FieldArrayRenderProps;
  /// The array managed by the FieldArray.
  sequences: SequenceIdentifierWithSource[];
}

function getFasta(sequences: SequenceIdentifierWithSource[]): {
  Dna: Sequence;
  source: string;
} {
  const records = [];
  const sources = [];
  for (const sequence of sequences) {
    if ("Dna" in sequence) {
      records.push(...sequence.Dna.records);
      sources.push(sequence.source);
    }
  }
  return { Dna: { records }, source: sources.join("\n") };
}

function updateFasta(
  sequences: SequenceIdentifierWithSource[],
  source: string,
  sequence: Sequence,
): SequenceIdentifierWithSource[] {
  const ids: SequenceIdentifierWithSource[] = sequences.filter(
    (x) => "Id" in x,
  );
  return ids.concat([{ Dna: sequence, source: source }]);
}

interface AnInputProps {
  // Callback that adds the AN but might return an error instead.
  onAdd: (an: string) => Result<undefined, string>;
}

export const AnInput = (props: AnInputProps) => {
  const [newAn, setNewAn] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);

  const [debouncedValue, { isPending }] = useDebounce(newAn, 400);
  useEffect(() => {
    if (debouncedValue) {
      setBusy(true);
      setMessage("");
      const an = debouncedValue.trim().toUpperCase();
      ncbi.title(an).then((result) => {
        if (result) {
          setMessage(result);
          setError(false);
        } else {
          setMessage(`Couldn't find ${debouncedValue} in GenBank`);
          setError(true);
        }
        setBusy(false);
      });
    } else {
      setMessage("");
    }
  }, [debouncedValue]);

  async function addAn(
    e:
      | React.MouseEvent<HTMLButtonElement>
      | React.KeyboardEvent<HTMLInputElement>,
  ) {
    for (const entry of newAn.split(",")) {
      const an = entry.trim().toUpperCase();
      setMessage("");
      setError(false);
      setBusy(true);
      const title = await ncbi.title(an);
      setBusy(false);
      if (title) {
        const result = props.onAdd(an);
        if (result.ok) {
          setMessage(`Added ${title}`);
          setError(false);
        } else {
          setMessage(result.error);
          setError(true);
          return;
        }
      } else {
        setMessage(`Couldn't find ${an} in GenBank`);
        setError(true);
        return;
      }
    }
    setNewAn("");
  }
  return (
    <div>
      <div className="flex">
        <div className="relative flex-1">
          <input
            className="flex-1 border rounded-l w-full leading-none p-2 outline-blue-500 -mr-1"
            placeholder="AN123.45"
            aria-label="Accession number"
            value={newAn}
            autoComplete="off"
            onKeyDown={(e) => e.key === "Enter" && addAn(e)}
            onChange={(e) => setNewAn(e.currentTarget.value)}
          />
        </div>
        <button
          className="bg-secondary enabled:hover:opacity-90 text-white disabled:bg-black/10 disabled:text-black/20 transition rounded-r px-4"
          type="button"
          disabled={isPending() || busy}
          onClick={addAn}
        >
          Add AN
        </button>
      </div>
      <div className={error ? "text-red-500 " : ""}>
        {(isPending() ? "" : message) || "\xa0"}
      </div>
    </div>
  );
};

/// Editable card, to be used in the `render` method of a Formik
/// FieldArray. https://formik.org/docs/api/fieldarray
export const OrganismForm = (props: OrganismFormProps) => {
  const { arrayHelpers, index, sequences } = props;
  const anTags = sequences
    .flatMap((s) => ("Id" in s && s.Id ? [s.Id] : []))
    .map((an, j) => (
      <a
        target="_blank"
        href={ncbi.url(an)}
        key={an}
        className="opaque"
        rel="noreferrer"
      >
        <div className="hover:bg-primary font-mono font-thin tracking-tight flex items-center mr-1 mb-1 pl-2 rounded cursor-pointer">
          {an}{" "}
          <div className="flex px-1 rounded-lg ml-1 h-4 w-4 mr-1 hover:bg-secondary hover:text-white">
            <RemoveButton
              className="w-5 -mx-[2px]"
              onClick={(e) => {
                arrayHelpers.remove(j);
                e.preventDefault();
              }}
            />
          </div>
        </div>
      </a>
    ));

  const { Dna: sequence, source } = getFasta(sequences);
  const [recognized, setRecognized] = useState(true);

  return (
    <div>
      <FormInput
        label="Name"
        name={`organisms.${index}.name`}
        suggestions={Object.keys(anMap)}
        onAcceptSuggestion={(hazardName) => {
          let ans = (anMap as Record<string, string[]>)[hazardName];
          if (ans) {
            setRecognized(true);
            ans = [...new Set(ans)];
            ans.sort();
            arrayHelpers.form.setFieldValue(
              `organisms.${index}.sequences`,
              ans.map((an) => ({ Id: an })),
            );
          } else {
            setRecognized(false);
          }
        }}
        onBlur={(e: any) => {
          if (e.target.value) {
            setRecognized(Object.hasOwn(anMap, e.target.value));
          }
        }}
        placeholder="Type to search, or enter a custom name"
      />
      {!recognized ? (
        <p className="my-2 text-sm">
          <FontAwesomeIcon icon={faWarning} className="mr-2" />
          This organism is not recognized as a hazard by SecureDNA, but you can
          still request an exemption in case it becomes recognized in the
          future.
        </p>
      ) : undefined}
      <div className="flex items-baseline justify-between">
        <h3 className="font-bold mt-4 mb-2">Accessions</h3>
        <LinkButton
          className="text-sm"
          type="button"
          onClick={() =>
            arrayHelpers.form.setFieldValue(`organisms.${index}.sequences`, [])
          }
        >
          Clear all
        </LinkButton>
      </div>
      <div className="flex flex-wrap mb-4">
        {anTags.length ? (
          anTags
        ) : (
          <span className="text-sm">
            No accessions selected. Specify a hazard above, or enter accession
            numbers from GenBank below.
          </span>
        )}
      </div>

      <AnInput
        onAdd={(an) => {
          if (an && props.sequences.every((x) => !("Id" in x) || x.Id !== an)) {
            arrayHelpers.push({ Id: an });
            return { ok: true, value: undefined };
          }
          return { ok: false, error: "Already included" };
        }}
      />

      <div>
        <FastaField
          source={source}
          data={sequence}
          setter={(newSource, newSequence) => {
            arrayHelpers.form.setFieldValue(
              `organisms.${index}.sequences`,
              updateFasta(sequences, newSource, newSequence),
            );
          }}
          showAsLinksIfEmpty={true}
        />
      </div>
    </div>
  );
};
