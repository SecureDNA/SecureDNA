# For more examples see https://github.com/oxalica/rust-overlay/issues/129
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        with pkgs;
        {
          devShells.default = mkShell {
            # 👇 we can just use `rustToolchain` here:
            buildInputs = [
              # Rust dev deps
              libfaketime # for certificate tests
              openssl
              zlib
              wasm-pack

              # Rust tools
              rustToolchain
              # We want the unwrapped version, wrapped comes with nixpkgs' toolchain
              rust-analyzer-unwrapped

              # Frontend deps (run npm install separately)
              nodejs-18_x

              # Other tools
              earthly
              gh # github cli tool
              jq
              just # justfile runner
              google-cloud-sdk # for building arm
            ];
            # Environment variables
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          };
        }
      );
}
