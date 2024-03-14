// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(target_pointer_width = "64")] // code assumes usize::BITS > u32::BITS
pub fn scan(db_dir: &std::path::Path) -> anyhow::Result<()> {
    use crate::{Entry, HazardLookupTable};
    use anyhow::Context;
    use std::{fs::File, io::BufReader};

    type BitVec = bitvec::vec::BitVec<usize, bitvec::prelude::Lsb0>;

    let mut used_hlt_indices = BitVec::repeat(false, u32::MAX as usize + 1);

    for byte in 0u8..=255 {
        let name = hex::encode([byte]);

        eprintln!("[Loading file {name}...]");
        let file = match File::open(db_dir.join(&name)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => Err(e).with_context(|| format!("failed to open db file {name}"))?,
        };

        let entries = Entry::read_all_from_reader(BufReader::new(file))
            .with_context(|| format!("failed to read entries from {name}"))?;

        for entry in entries {
            let metadata = entry
                .metadata()
                .with_context(|| format!("failed to decode metadata for entry {:?}", entry))?;
            used_hlt_indices.set(metadata.hlt_index as usize, true);
        }
    }

    eprintln!("[Loading HLT...]");
    let hlt = HazardLookupTable::read(db_dir).context("failed to read HLT")?;

    eprintln!("[Scanning...]");
    for key in hlt.keys() {
        if !used_hlt_indices.get(key as usize).unwrap() {
            println!("{}", key);
        }
    }

    Ok(())
}
