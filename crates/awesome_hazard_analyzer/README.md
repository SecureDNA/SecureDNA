# Awesome Hazard Analyzer (AHA)

AHA is a way to bypass full SecureDNA network cryptography and read hazards straight from disk. 
It is a combination of `hdb`, `doprf_client` and `synthclient` that ignores HDB servers and key servers.

## Running
Always run AHA in release mode `cargo run --release --bin - awesomehazardanalyzer`: A Rust crate combining `hdb` and `synthclient` into one fast local hazard analyser which bypasses crypto and networking
`

`--hdb-dir <DIR>` should contain the encrypted HDB database

`--secret-key <KEY>` is the master key to the HDB database.
We do not need key fragments to read from disk, we need the master key that was used to generate it.

`--debug` will toggle large debugging output in JSON to disk. Only enable this if you have sufficient space in `./output`

`--summary` will dump a CSV file containing all hazards, their results and the found ANs/names.
Usually used to import into a spreadsheet for comparison.

`--no-aa` will skip the generation of Amino Acid windows.
Useful for debugging matches.

`--no-dna` will skip the generation of DNA and Reverse DNA windows.
Useful for debugging matches.
