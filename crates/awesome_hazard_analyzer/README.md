# Awesome Hazard Analyzer (AHA)

AHA is a way to bypass full SecureDNA network cryptography and read hazards straight from disk. 
It is a combination of `hdb`, `doprf_client` and `synthclient` that ignores HDB servers and key servers.

## Running
Always run AHA in release mode `cargo run --release --bin - awesomehazardanalyzer`: A Rust crate combining `hdb` and `synthclient` into one fast local hazard analyser which bypasses crypto and networking
`

`--hdb-dir <DIR>` should contain the encrypted HDB database

`--secret-key <KEY>` is the master key to the HDB database.
We do not need key fragments to read from disk, we need the master key that was used to generate it.

`--debug` will toggle large debugging output in JSON to disk. Only enable this if you have sufficient space in `./output`.
This provides details for hits grouped by FASTA record, after window consolidation has taken place.
Three directories are created:
- `.no-rs` contains hits for which 'reverse_screened' is false. Derived from `consolidation.results`.
- `.with-rs` contains the hits for which 'reverse_screened' is true. Derived from `consolidation.results`.
- `.overlap` contains hits that were removed due to overlap with other hits. Derived from `consolidation.debug.removed_overlaps`.

`--unconsolidated` will toggle the output of all hits before consolidation into hit regions. This output will be very large if many records are screened. Derived from `consolidation.debug.unconsolidated_responses`. Includes all reverse screened hits. The output is written to a directory named `unconsolidated-hits-<timestamp>` which will contain one JSON file per record screened.

`--summary` will dump a CSV file containing all hazards, their results and the found ANs/names.
Derived from `consolidation.debug.unconsolidated_responses`, therefore counts each hit as a separate hit region (no window consolidation).
Usually used to import into a spreadsheet for comparison.

`--no-aa` will skip the generation of Amino Acid windows.
Useful for debugging matches.

`--no-dna` will skip the generation of DNA and Reverse DNA windows.
Useful for debugging matches.

## Output

### `unconsolidated-hits-<timestamp>`

This directory contains one JSON file per record screened.
The format is as follows:

```json
{
  "record": 0,
  "seq_range_start": 100,
  "seq_range_end": 160,
  "hdb_response": {
    "synthesis_permission": "granted",
    "most_likely_entity": {
      "name": "Organism_A",
      "entity_type": "Bacteria",
      "ans": [
        "GENOME_ID_001",
        "GENOME_ID_002"
      ],
      "tags": [
        "RegulationTag_1",
        "RegulationTag_2",
      ]
    },
    "entities": [
      {
        "name": "Organism_A",
        "entity_type": "Bacteria",
        "ans": [
          "GENOME_ID_001",
          "GENOME_ID_002"
        ],
        "tags": [
          "RegulationTag_1",
          "RegulationTag_2",
        ]
      },
      {
        "name": "Organism_B",
        "entity_type": "Bacteria",
        "ans": [
          "GENOME_ID_003",
          "GENOME_ID_004"
        ],
        "tags": [
          "RegulationTag_1",
          "RegulationTag_2",
          "RegulationTag_3",
          "RegulationTag_4",
          "RegulationTag_5"
        ]
      }
    ],
    "an_likelihood": 0,
    "provenance": "AAWildType",
    "reverse_screened": false,
    "window_gap": 60,
    "exempt": false
  }
}
```
