// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(dead_code)]

use std::io::{self, Write};
use std::process::{Command, Output};

const TARGET_DIR: &str = "target_wasm";

#[cfg(feature = "wasm")]
fn main() {
    println!("cargo:rerun-if-changed=certificates/src/");
    println!("cargo:rerun-if-changed=quickdna/src/");
    println!("cargo:rerun-if-changed=screening/src/");

    // Don't run wasm-pack if rust-analyzer is running this build script
    // Note: both these are a bit hackish, and one needs extra configuration
    // * RA_RUSTC_WRAPPER is only set if rust-analyzer is configured to act as a rustc wrapper.
    //   This is the default, but it is only invoked this way some of the time, so this doesn't cover all invocations.
    // * IS_RUST_ANALYZER isn't an upstream thing, but rather an environment variable that needs to be manually added to
    //   rust-analzyer's config > Cargo > Extra Env. This works 100%, but needs manual setup.
    // See https://github.com/rust-lang/rust-analyzer/blob/85493dfdb045ce78db78c6d50e8015bdb442cc62/crates/project-model/src/build_scripts.rs#L109C1-L117
    // and https://github.com/rust-lang/rust-analyzer/pull/15115 for more details
    let is_rust_analyzer =
        option_env!("RA_RUSTC_WRAPPER").is_some() || option_env!("IS_RUST_ANALYZER").is_some();
    if !is_rust_analyzer {
        do_wasm_pack();
    }
}

#[cfg(not(feature = "wasm"))]
fn main() {
    println!("cargo:warning=Feature `wasm` disabled; skipping wasm build.")
}

fn ensure_wasm_pack_success(output: Output) {
    io::stderr().write_all(&output.stderr).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let wasm_bindgen_failed = stderr.contains("Error: Running the wasm-bindgen CLI");
    assert!(!wasm_bindgen_failed);
    assert!(output.status.success());
}

fn wasm_pack(dir: &str, target: &str, out_dir: &str) {
    let extra_flags = option_env!("WASM_PACK_FLAGS")
        .unwrap_or("")
        .split(' ')
        .filter(|x| !x.is_empty());

    let mut target_dir = std::env::current_dir().unwrap();
    target_dir.push(TARGET_DIR);
    let output = Command::new("wasm-pack")
        .current_dir(dir)
        .args(["build", "--target", target])
        .args(extra_flags)
        .args(["--out-dir", out_dir])
        .args(["--target-dir", target_dir.to_str().unwrap()])
        .output()
        .unwrap();

    ensure_wasm_pack_success(output);
}

/// Currently unused. We weren't quite getting the speedup we wanted from
/// wasm-bindgen-rayon, and the build/version requirements are too thorny.
/// (Splitting the work between Workers seems to work almost as well.)
fn wasm_pack_rayon(dir: &str, target: &str, out_dir: &str) {
    let output = Command::new("rustup")
        .current_dir(dir)
        .env(
            "RUSTFLAGS",
            "-C target-feature=+atomics,+bulk-memory,+mutable-globals",
        )
        .args(["run", "nightly-2022-12-12"])
        .args(["wasm-pack", "build", ".", "--target", target])
        .args(["--out-dir", out_dir])
        .args(["--", "-Z", "build-std=panic_abort,std"])
        .output()
        .unwrap();

    ensure_wasm_pack_success(output);
}

fn do_wasm_pack() {
    let expected_version = "0.12";
    let installation_instructions = format!(
        r#"
- download a binary from https://rustwasm.github.io/wasm-pack/
- or run `cargo install --version '^{expected_version}' wasm-pack`
"#
    );
    let version = Command::new("wasm-pack")
        .arg("--version")
        .output()
        .unwrap_or_else(|_| {
            panic!("\n\nwasm-pack not found, install it:{installation_instructions}\n")
        });
    let wasm_pack_version = String::from_utf8(version.stdout).unwrap();
    let wasm_pack_version = wasm_pack_version.trim_end();
    assert!(
        wasm_pack_version.starts_with(&format!("wasm-pack {expected_version}.")),
        "\n\nwrong version: {wasm_pack_version}, install {expected_version} with:{installation_instructions}\n"
    );

    // Build the WASM binaries and TypeScript interface:
    for dir in ["certificates", "quickdna", "screening"] {
        if dir == "screening" {
            // https://rustwasm.github.io/wasm-bindgen/examples/wasm-in-web-worker.html#building--compatibility
            wasm_pack(dir, "web", "pkg");
        } else {
            // Build for a web bundler (Vite/Rollup):
            wasm_pack(dir, "bundler", "pkg");
        }
    }

    // Run tsgen to generate TypeScript type definitions.
    Command::new("node")
        .current_dir("../../frontend/tsgen")
        .arg("main.js")
        .status()
        .unwrap();
}
