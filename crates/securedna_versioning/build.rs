// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use vergen_git2::{Emitter, Git2Builder};

fn main() {
    let git2 = Git2Builder::all_git().unwrap();
    Emitter::default()
        .add_instructions(&git2)
        .unwrap()
        .emit()
        .unwrap();
}
