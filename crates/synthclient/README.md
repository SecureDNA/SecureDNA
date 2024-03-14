# synthclient

This is a Rust webserver that accepts FASTA strings submitted for DNA synthesis, generates windows from those strings, and then communicates with other components to hash the windows and check them for hazards.

It may be easiest to run it as part of `earthly +dev` (see [repo root README](../README.md)), but you can also run it independently. For an example of startup, see `bin/local_test_environment.sh`

For an example request to the synthclient API, see `Example usage` in the repo's README.md
