// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs::File;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};

use metrics::histogram;
use rayon::prelude::*;
use tracing::warn;

use super::Entry;

// Allow DatabaseFile to read non-Files for testing
trait DataSource {
    fn len(&self) -> io::Result<u64>;

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
}

impl DataSource for File {
    fn len(&self) -> io::Result<u64> {
        self.metadata().map(|m| m.len())
    }

    #[cfg(unix)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        FileExt::read_exact_at(self, buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        // This implementation is copied from https://doc.rust-lang.org/src/std/os/unix/fs.rs.html
        // except `read_at` is replaced by `std::os::windows::fs::FileExt::seek_read`.
        //
        // Beware: `seek_read` trashes the file cursor position (even though it doesn't take `&mut self`!)
        // Thankfully, none of our code that uses this trait depends on the file cursor position.
        while !buf.is_empty() {
            match self.seek_read(buf, offset) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    offset += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if !buf.is_empty() {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        } else {
            Ok(())
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn read_exact_at(&self, mut _buf: &mut [u8], mut _offset: u64) -> io::Result<()> {
        // In WebAssembly, the hdb crate is only depended on for its types, namely by doprf_client.
        // We never call this function and can leave it unimplemented.
        // TODO: split the types into a separate crate.
        unimplemented!()
    }
}

/// A hash in the HDB. Its 32 bytes are derived from `CompletedHashValue` in
/// `doprf`, which is internally a
/// [curve25519_dalek::ristretto::CompressedRistrettoPoint].
///
/// The first byte is used as a "prefix byte", and is used to split the HDB into
/// files: `hdb/00`, `hdb/02` ... `hdb/fe`. The remaining bytes are used as a
/// binary search index within that file (see [Entry].)
///
/// ## Distribution
///
/// The bits in an EntryHash are not all uniformly 0 or 1. Two of its 256 bits
/// are always unset if the EntryHash was properly created from a
/// `CompletedHashValue` (Ristretto point):
///
/// 1. The least significant bit of the first byte ("bit 7") is unset. (This
///    encodes that the underlying FieldElement is
///    ["non-negative"](https://doc-internal.dalek.rs/curve25519_dalek/backend/serial/u64/field/struct.FieldElement51.html#method.is_negative),
///    which is a requirement for FieldElements used in the Ristretto
///    algorithm.)
///
///    This is why the "prefix byte" is always even, and why there are no files
///    called `hdb/01`, `hdb/03` ... `hdb/ff`.
///
/// 2. The most significant bit of the last byte ("bit 248") is also unset.
///    (This is because the underlying FieldElement fits in 255 bits, so the
///    little-endian most significant bit [is
///    zero](https://github.com/dalek-cryptography/curve25519-dalek/blob/4583c472f53c912dbc50466b8cae222a3c582176/src/backend/serial/u64/field.rs#L440-L443).)
///
pub(crate) type EntryHash = [u8; Entry::HASH_LENGTH];

#[derive(Debug, PartialEq, Eq)]
struct DatabaseIndex {
    num_entries: u64,
    samples: Vec<EntryHash>,
}

impl DatabaseIndex {
    fn new(file: &impl DataSource, index_byte_len: usize) -> io::Result<Self> {
        let file_len = file.len()?;

        if file_len % (Entry::BYTE_LENGTH as u64) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("file size not a multiple of {}", Entry::BYTE_LENGTH),
            ));
        }

        let num_entries = file_len / Entry::BYTE_LENGTH as u64;
        let num_samples = if num_entries < 2 {
            // only happens in tests
            num_entries as usize
        } else {
            (index_byte_len / std::mem::size_of::<EntryHash>()).clamp(2, num_entries as usize)
        };

        let mut this = Self {
            num_entries,
            samples: vec![EntryHash::default(); num_samples],
        };

        let sample_idx_to_entry_idx = this.sample_idx_to_entry_idx();
        for (sample_index, hash) in this.samples.iter_mut().enumerate() {
            let entry_index = sample_idx_to_entry_idx(sample_index);
            let entry_byte_offset = entry_index * Entry::BYTE_LENGTH as u64;
            file.read_exact_at(hash, entry_byte_offset)?;
        }

        Ok(this)
    }

    fn read(mut reader: impl io::Read) -> io::Result<Self> {
        let mut read_u64 = || -> io::Result<u64> {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        };

        let num_entries = read_u64()?;
        let num_samples = read_u64()?;
        if num_samples > num_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "index must not be larger than original file",
            ));
        }
        let num_samples: usize = num_samples
            .try_into()
            .expect("Too many samples to fit in memory");
        let mut samples = vec![EntryHash::default(); num_samples];
        for sample in &mut samples {
            reader.read_exact(sample)?;
        }

        if samples.windows(2).any(|window| window[0] >= window[1]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "samples not monotonically increasing",
            ));
        }

        Ok(Self {
            num_entries,
            samples,
        })
    }

    fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
        let num_samples: u64 = self
            .samples
            .len()
            .try_into()
            .expect("HDB index should fit in a file.");
        writer.write_all(&self.num_entries.to_le_bytes())?;
        writer.write_all(&num_samples.to_le_bytes())?; // Easy way to detect file truncation
        for sample in &self.samples {
            writer.write_all(sample)?;
        }
        Ok(())
    }

    /// Return the Entry index that corresponds with the given sample index
    fn sample_idx_to_entry_idx(&self) -> impl Fn(usize) -> u64 {
        let num_entries = self.num_entries;
        let num_samples = self.samples.len();
        move |sample_index| {
            // The same logic as in calculate_probe_location() applies...
            // sample_index < num_samples < num_entries < u64::MAX so this won't overflow.
            (sample_index as u128 * (num_entries - 1) as u128 / (num_samples - 1).max(1) as u128)
                as u64
        }
    }

    /// Return a subrange of the file that a query may be in.
    ///
    /// If the query could possibly be in the file, returns Some((lower index, upper_index, lower_hash, upper_hash)):
    /// * lower_index/upper_index are inclusive lower/upper bounds for the range of Entry indices that could hold query
    /// * lower_hash is guaranteed <= the lower bound Entry hash
    /// * upper_hash is guaranteed >= the upper bound Entry hash
    /// If the query falls outside the file, None is returned
    fn position_range(&self, query: &EntryHash) -> Option<(u64, u64, EntryHash, EntryHash)> {
        let (start_sample_index, end_sample_index) = match self.samples.binary_search(query) {
            Ok(sample_index) => (sample_index, sample_index),
            Err(end_sample_index) if (1..self.samples.len()).contains(&end_sample_index) => {
                (end_sample_index - 1, end_sample_index)
            }
            _ => return None,
        };

        let sample_idx_to_entry_idx = self.sample_idx_to_entry_idx();
        let start_index = sample_idx_to_entry_idx(start_sample_index);
        let end_index = sample_idx_to_entry_idx(end_sample_index);
        let start_val = self.samples[start_sample_index];
        let end_val = self.samples[end_sample_index];

        Some((start_index, end_index, start_val, end_val))
    }
}

#[derive(Debug)]
struct DatabaseFile<F> {
    file: F,
    index: DatabaseIndex,
}

impl DatabaseFile<File> {
    // Note: In order to safeguard against out-of-date indexes (which would lead to missed
    // hazards) this will only use indexes with a NEWER modification date than the entry data.
    fn open(
        entries_path: impl AsRef<Path>,
        index_path: impl AsRef<Path>,
    ) -> io::Result<Option<Self>> {
        let entries_file = match File::open(&entries_path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            x => x,
        }?;

        let trivial_index = DatabaseIndex::new(&entries_file, 0)?;

        let is_recent = |file: &File| -> io::Result<bool> {
            let entries_mtime = entries_file.metadata().and_then(|m| m.modified())?;
            let mtime = file.metadata().and_then(|m| m.modified())?;
            Ok(mtime > entries_mtime)
        };

        let looks_plausible = |index: &DatabaseIndex| {
            // These don't depend on index size, so sanity check against the trival index.
            index.num_entries == trivial_index.num_entries
                && index.samples.first() == trivial_index.samples.first()
                && index.samples.last() == trivial_index.samples.last()
        };

        let index_path = index_path.as_ref();
        let index = match File::open(index_path) {
            Ok(index_file) if is_recent(&index_file)? => {
                let reader = io::BufReader::new(index_file);
                let index = DatabaseIndex::read(reader)?;
                if looks_plausible(&index) {
                    index
                } else {
                    warn!("Ignoring mismatching index: {index_path:?}");
                    trivial_index
                }
            }
            Ok(_) => {
                warn!("Ignoring out-of-date index: {index_path:?}");
                trivial_index
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                warn!("Missing index: {index_path:?}");
                trivial_index
            }
            Err(err) => Err(err)?,
        };

        Ok(Some(Self {
            file: entries_file,
            index,
        }))
    }
}

impl<F: DataSource> DatabaseFile<F> {
    /// Assuming values in the db are uniformly distributed, determine the best-guess query location.
    fn calculate_probe_location(
        query: &EntryHash,
        start_index: u64,
        start_val: &EntryHash,
        end_index: u64,
        end_val: &EntryHash,
    ) -> u64 {
        if end_index == start_index {
            return start_index;
        }

        // MSBs = Most Significant Bits
        // We look at the first 8 bytes, *not counting the prefix byte*, which is in every database
        // entry in this file. This should be plenty to disambiguate in nearly every case. This is
        // also not affected by the known always-zero bits in the hashes (bit 7 and bit 248).
        let query_msbs = u64::from_be_bytes(
            query[1..9]
                .try_into()
                .expect("Couldn't extract 8 bytes from 32"),
        );
        let start_msbs = u64::from_be_bytes(
            start_val[1..9]
                .try_into()
                .expect("Couldn't extract 8 bytes from 32"),
        );
        let end_msbs = u64::from_be_bytes(
            end_val[1..9]
                .try_into()
                .expect("Couldn't extract 8 bytes from 32"),
        );

        let query_offset = query_msbs - start_msbs;
        let end_offset = end_msbs - start_msbs;

        // We can compute this using integer arithmetic because a u64 times a u64 can't overflow a
        // u128.
        let index_corresponding_to_fraction =
            ((end_index - start_index) as u128 * query_offset as u128) / end_offset as u128;

        let tentative_result = start_index + index_corresponding_to_fraction as u64;
        u64::min(tentative_result, end_index)
    }

    fn search(&self, query: &EntryHash) -> io::Result<Option<Entry>> {
        let entry_size = Entry::BYTE_LENGTH as u64;

        // start/end are the inclusive range of indices that query could match
        // start_val is a hash at most the hash of the Entry at start
        // end_val is a hash at least the hash of the Entry at end
        let (mut start, mut end, mut start_val, mut end_val) =
            match self.index.position_range(query) {
                Some(search_range) => search_range,
                None => return Ok(None),
            };

        let mut num_probes = 0;

        while start <= end {
            let probe_location =
                Self::calculate_probe_location(query, start, &start_val, end, &end_val);

            num_probes += 1;

            let byte_location = probe_location * entry_size;

            let mut entry_bytes = [0_u8; Entry::BYTE_LENGTH];
            self.file.read_exact_at(&mut entry_bytes, byte_location)?;
            let entry: Entry = entry_bytes.into();

            let entry_hash = entry.hash_bytes();

            match entry_hash.cmp(query) {
                std::cmp::Ordering::Less => {
                    start = probe_location + 1;
                    start_val = entry_hash;
                }
                std::cmp::Ordering::Equal => {
                    histogram!("query_probes").record(num_probes as f64);
                    return Ok(Some(entry));
                }
                std::cmp::Ordering::Greater => {
                    end = probe_location - 1;
                    end_val = entry_hash;
                }
            }
        }

        histogram!("query_probes").record(num_probes as f64);
        Ok(None)
    }
}

// Overwrites file (mostly) atomically.
//
// Uses the closure to populate a new WIP file then move it into place only
// after it's complete. This isn't secure against interference (e.g. another
// process moving another file into place of the WIP file during population)
// but it should gracefully handle multiple copies of itself racing.
fn overwrite_file(
    path: impl AsRef<Path>,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    // TODO: If we really want to be raceproof, create a nameless file via the
    // tmpfile option and link it at the end via linkat.
    let wip_path = path.as_ref().with_extension("wip");
    let mut wip_file = File::options()
        .write(true)
        .create_new(true)
        .open(&wip_path)?;
    let result = write(&mut wip_file).and_then(|_| std::fs::rename(&wip_path, &path));
    if result.is_err() {
        std::fs::remove_file(&wip_path)?;
    }
    result
}

pub struct Database {
    /// A slice of files at fixed indices (with Option to indicate no file at that index). 256
    /// bytes, to match the range of entry prefixes.
    files: [Option<DatabaseFile<File>>; 256],
}

impl Database {
    pub fn open(database_path: impl AsRef<Path>) -> io::Result<Self> {
        let database_path = database_path.as_ref();
        let index_dir_path = Self::index_dir_path(database_path);

        let md = std::fs::metadata(database_path)?;
        if !md.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput, // NotADirectory isn't stablized yet
                "database path must be a directory",
            ));
        }
        let hdb_is_empty = database_path.read_dir()?.next().is_none();
        if hdb_is_empty {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput, // NotADirectory isn't stablized yet
                "database path is empty",
            ));
        }

        let files: io::Result<Vec<_>> = (0u8..=255)
            .map(|byte| {
                let entries_path = Self::entries_path(database_path, byte);
                let index_path = Self::index_path(&index_dir_path, &entries_path);
                DatabaseFile::open(entries_path, index_path)
            })
            .collect();

        Ok(Self {
            files: files?.try_into().unwrap(),
        })
    }

    pub fn query(&self, query: &EntryHash) -> io::Result<Option<Entry>> {
        // Sanity check that bits 7 and 248 are not set

        // A correct ristretto point representation never sets these bits
        // If either of the the bits is set, its a failure of the calling code which should have prevented such a query
        // Just a reminder to a reader, bit order is always big endian, meaning the most significant bit comes first

        // you can notice that on disk, there are never any odd numbered files
        // this corresponds to 0 vs 1 in bit 7
        if query[0] & 1 == 1 {
            return Err(io::ErrorKind::InvalidInput.into());
        }

        // bit 248 is located in the last byte (31) at the most significant position (0)
        // this corresponds to 0 vs 128 in bit 0
        if query[31] & 128 == 128 {
            return Err(io::ErrorKind::InvalidInput.into());
        }

        let prefix = query[0];

        match &self.files[prefix as usize] {
            None => Ok(None),
            Some(file) => file.search(query),
        }
    }

    pub fn rebuild_index(database_path: impl AsRef<Path>, index_byte_len: usize) -> io::Result<()> {
        let database_path = database_path.as_ref();
        let index_dir_path = Self::index_dir_path(database_path);
        // We're expecting only half of possible prefixes to exist.
        let per_file_index_byte_len = index_byte_len / 128;

        match std::fs::create_dir(&index_dir_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }

        (0u8..255).into_par_iter().try_for_each(|byte| {
            let entries_path = Self::entries_path(database_path, byte);
            let index_path = Self::index_path(&index_dir_path, &entries_path);

            match File::open(entries_path) {
                Ok(entries_file) => {
                    let index = DatabaseIndex::new(&entries_file, per_file_index_byte_len)?;
                    // We overwrite files atomically to make it safe to rebuild indexes even if
                    // someone might be reading the HDB. This used to matter more in a prior
                    // version of the code where merely opening a database could write indexes,
                    // because several tests (running in parallel) were sharing the same HDB.
                    overwrite_file(index_path, |f| {
                        let mut writer = io::BufWriter::new(f);
                        index.write(&mut writer)?;
                        writer.flush()
                    })
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err),
            }
        })
    }

    // Returns subdir of database_path that index resides in
    fn index_dir_path(database_path: impl AsRef<Path>) -> PathBuf {
        database_path.as_ref().join("index")
    }

    // Returns filename for a particular prefix byte
    fn entries_path(database_path: impl AsRef<Path>, prefix_byte: u8) -> PathBuf {
        database_path.as_ref().join(hex::encode([prefix_byte]))
    }

    // Returns filename for the index of a particular entry_path
    fn index_path(index_dir_path: impl AsRef<Path>, entries_path: impl AsRef<Path>) -> PathBuf {
        let file_name = entries_path
            .as_ref()
            .file_name()
            .expect("entries_path must have filename");
        let mut index_path = index_dir_path.as_ref().join(file_name);
        index_path.set_extension("i");
        index_path
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use quickcheck::{quickcheck, Arbitrary, Gen};
    use tempfile;

    use super::*;

    #[derive(Clone, Debug)]
    struct IndexSize(usize);

    impl Arbitrary for IndexSize {
        fn arbitrary(g: &mut Gen) -> Self {
            // Using Vec::arbitrary(g) until g.gen_range(0..g.size()) is public
            Self(Vec::<()>::arbitrary(g).len() * 1024 * 1024)
        }
    }

    #[derive(Clone, Debug)]
    struct FakeFile(Vec<u8>);

    impl FakeFile {
        fn new(init: &[&[u8]]) -> Self {
            let bytes = init.iter().copied().flatten().copied().collect();
            Self(bytes)
        }

        fn hashes(&self) -> impl Iterator<Item = EntryHash> + '_ {
            self.0
                .chunks_exact(Entry::BYTE_LENGTH)
                .map(|entry| entry[..Entry::HASH_LENGTH].try_into().unwrap())
        }
    }

    impl DataSource for FakeFile {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len().try_into().expect("FakeFile data too large"))
        }

        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
            let offset: usize = offset.try_into().expect("offset too large");
            let src = &self.0[offset..];
            let len = src.len().min(buf.len());
            buf[..len].copy_from_slice(&src[..len]);
            Ok(())
        }
    }

    impl Arbitrary for FakeFile {
        fn arbitrary(g: &mut Gen) -> Self {
            let prefix = u8::arbitrary(g);
            // Using Vec::arbitrary(g) until g.gen_range(0..g.size()) is public
            let mut entries: Vec<_> = Vec::arbitrary(g)
                .iter()
                .map(|()| {
                    let mut hash = [0; Entry::BYTE_LENGTH];
                    hash[0] = prefix;
                    hash[1..].fill_with(|| u8::arbitrary(g));
                    hash
                })
                .collect();
            entries.sort();
            entries.dedup_by(|a, b| a[..Entry::HASH_LENGTH] == b[..Entry::HASH_LENGTH]);

            let bytes = entries.into_iter().flatten().collect();
            FakeFile(bytes)
        }
    }

    fn prev_hash(mut hash: EntryHash) -> Option<EntryHash> {
        let i = hash.iter().rposition(|&b| b > 0)?;
        hash[i] -= 1;
        hash[i + 1..].fill(255);
        Some(hash)
    }

    fn next_hash(mut hash: EntryHash) -> Option<EntryHash> {
        let i = hash.iter().rposition(|&b| b < 255)?;
        hash[i] += 1;
        hash[i + 1..].fill(0);
        Some(hash)
    }

    fn metadata(b: u8) -> [u8; Entry::BYTE_LENGTH - Entry::HASH_LENGTH] {
        [b; Entry::BYTE_LENGTH - Entry::HASH_LENGTH]
    }

    const INDEX_SIZES: [usize; 7] = [
        0,
        1,
        Entry::BYTE_LENGTH - 1,
        Entry::BYTE_LENGTH,
        2 * Entry::BYTE_LENGTH - 1,
        2 * Entry::BYTE_LENGTH,
        1024,
    ];

    fn new_database_file<F: DataSource>(
        file: F,
        index_byte_len: usize,
    ) -> io::Result<DatabaseFile<F>> {
        let index = DatabaseIndex::new(&file, index_byte_len)?;
        Ok(DatabaseFile { file, index })
    }

    fn temp_hdb() -> tempfile::TempDir {
        let rest_of_entry = [0; Entry::BYTE_LENGTH - 2];

        // These values are somewhat arbitrary except:
        // * The first byte of a hash needs to match the name of the file it's in.
        // * The hashes should be in ascending order, so we set the second byte accordingly.
        let entries00 = FakeFile::new(&[
            &[0x00, 12],
            &rest_of_entry,
            &[0x00, 34],
            &rest_of_entry,
            &[0x00, 123],
            &rest_of_entry,
            &[0x00, 234],
            &rest_of_entry,
        ]);
        let entries02 = FakeFile::new(&[
            &[0x02, 11],
            &rest_of_entry,
            &[0x02, 99],
            &rest_of_entry,
            &[0x02, 111],
            &rest_of_entry,
        ]);

        let hdb_dir = tempfile::tempdir().unwrap();
        let index_dir = hdb_dir.path().join("index");
        std::fs::create_dir(&index_dir).unwrap();

        for (id, entry_data) in [("00", entries00), ("02", entries02)] {
            let entry_filename = hdb_dir.path().join(id);
            let mut entry_file = File::create(&entry_filename).unwrap();
            entry_file.write_all(&entry_data.0).unwrap();

            let index_filename = index_dir.join(id).with_extension("i");
            let index_byte_len = 1000;
            let index = DatabaseIndex::new(&entry_data, index_byte_len).unwrap();
            let mut index_file = File::create(&index_filename).unwrap();
            index.write(&mut index_file).unwrap();

            let mtime = |f: &File| f.metadata().and_then(|m| m.modified()).unwrap();

            // The database has safeguards to prevent using an out-of-date index, so we
            // need to adjust the modification times to make it clear the index is newer.
            // We don't use filetime::FileTime::zero() because Windows doesn't like that.
            let before_index = mtime(&index_file) - Duration::from_secs(10);
            entry_file.set_modified(before_index).unwrap();

            assert!(mtime(&entry_file) < mtime(&index_file));
        }

        hdb_dir
    }

    #[test]
    fn test_empty_file_finds_nothing() {
        for index_size in INDEX_SIZES {
            let file = FakeFile::new(&[]);
            let dbf = new_database_file(file, index_size).unwrap();

            assert!(dbf.search(&[0; Entry::HASH_LENGTH]).unwrap().is_none());
            assert!(dbf.search(&[123; Entry::HASH_LENGTH]).unwrap().is_none());
            assert!(dbf.search(&[0xFF; Entry::HASH_LENGTH]).unwrap().is_none());
        }
    }

    #[test]
    fn test_single_record_file() {
        for index_size in INDEX_SIZES {
            let hash = [123; Entry::HASH_LENGTH];
            let file = FakeFile::new(&[&hash, &metadata(234)]);
            let dbf = new_database_file(file, index_size).unwrap();

            assert!(dbf.search(&[0; Entry::HASH_LENGTH]).unwrap().is_none());
            assert!(dbf.search(&prev_hash(hash).unwrap()).unwrap().is_none());

            let found = dbf.search(&hash).unwrap().unwrap();
            assert_eq!(found.hash_slice(), &hash);
            assert_eq!(found.metadata_slice(), &metadata(234));

            assert!(dbf.search(&next_hash(hash).unwrap()).unwrap().is_none());
            assert!(dbf.search(&[255; Entry::HASH_LENGTH]).unwrap().is_none());
        }
    }

    #[test]
    fn test_two_record_file() {
        for index_size in INDEX_SIZES {
            let hash1 = [123; Entry::HASH_LENGTH];
            let mut hash2 = [135; Entry::HASH_LENGTH];
            hash2[0] = 123; // DatabaseFiles only support a uniform first byte across hashes

            let file = FakeFile::new(&[&hash1, &metadata(234), &hash2, &metadata(246)]);
            let dbf = new_database_file(file, index_size).unwrap();

            assert!(dbf.search(&[0; Entry::HASH_LENGTH]).unwrap().is_none());
            assert!(dbf.search(&prev_hash(hash1).unwrap()).unwrap().is_none());

            let found = dbf.search(&hash1).unwrap().unwrap();
            assert_eq!(found.hash_slice(), &hash1);
            assert_eq!(found.metadata_slice(), &metadata(234));

            assert!(dbf.search(&next_hash(hash1).unwrap()).unwrap().is_none());
            assert!(dbf.search(&prev_hash(hash1).unwrap()).unwrap().is_none());

            let found = dbf.search(&hash2).unwrap().unwrap();
            assert_eq!(found.hash_slice(), &hash2);
            assert_eq!(found.metadata_slice(), &metadata(246));

            assert!(dbf.search(&next_hash(hash2).unwrap()).unwrap().is_none());
            assert!(dbf.search(&[255; Entry::HASH_LENGTH]).unwrap().is_none());
        }
    }

    #[test]
    fn test_database_file_reads_saved_indexes() {
        let hdb = temp_hdb();
        let entries_path = hdb.path().join("00");
        let index_path = hdb.path().join("index/00.i");

        let dbf = DatabaseFile::open(entries_path, index_path)
            .unwrap()
            .unwrap();

        assert!(dbf.index.samples.len() > 2);
    }

    #[test]
    fn test_database_file_can_be_opened_even_if_unable_to_find_index() {
        let hdb = temp_hdb();
        let entries_path = hdb.path().join("00");

        let tmpdir = tempfile::tempdir().unwrap();
        let index_path = tmpdir.path().join("00.i");

        DatabaseFile::open(entries_path, index_path)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn test_database_file_rejects_mismatched_indexes() {
        let hdb = temp_hdb();
        let entries_path = hdb.path().join("00");
        let index_path = hdb.path().join("index/02.i");

        let dbf = DatabaseFile::open(entries_path, index_path)
            .unwrap()
            .unwrap();

        assert!(dbf.index.samples.len() == 2);
    }

    #[test]
    fn invalid_entries_do_not_panic_database() {
        let hdb_path = temp_hdb();
        let db = Database::open(&hdb_path).unwrap();
        let mut invalid_hash1: EntryHash = Default::default();
        *invalid_hash1.first_mut().unwrap() = !0;
        let mut invalid_hash2: EntryHash = Default::default();
        *invalid_hash2.last_mut().unwrap() = !0;

        // I don't really care whether these return Ok(None) or Err(_).
        // I just think they shouldn't panic or find results.
        assert!(!matches!(db.query(&invalid_hash1), Ok(Some(_))));
        assert!(!matches!(db.query(&invalid_hash2), Ok(Some(_))));
    }

    quickcheck! {
        fn database_file_can_find_all_its_hashes(file: FakeFile, index_size: IndexSize) -> bool {
            let dbf = new_database_file(file.clone(), index_size.0).unwrap();
            file.hashes()
                .all(|hash| matches!(dbf.search(&hash), Ok(Some(e)) if e.hash_bytes() == hash))
        }

        fn database_file_does_not_find_adjacent_hashes(
            file: FakeFile,
            index_size: IndexSize
        ) -> bool {
            let hashes: Vec<_> = file.hashes().collect();
            let dbf = new_database_file(file, index_size.0).unwrap();

            let adjacent_hashes = hashes
                .iter()
                .flat_map(|&h| [prev_hash(h), next_hash(h)])
                .flatten();

            adjacent_hashes
                .filter(|h| !hashes.contains(h))
                .all(|h| matches!( dbf.search(&h), Ok(None)))
        }

        fn indexes_can_be_saved(file: FakeFile, index_size: IndexSize) -> bool {
            let index = DatabaseIndex::new(&file, index_size.0).unwrap();
            let mut buf = vec![];
            index.write(&mut buf).unwrap();
            let reloaded_index = DatabaseIndex::read(&*buf).unwrap();
            index == reloaded_index
        }
    }
}
