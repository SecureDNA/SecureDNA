// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use tar::{Builder, Header};

pub enum DebugOutputSink {
    Directory(DirectoryOutput),
    Tarred(Box<Mutex<TarredOutput>>), // clippy wants this boxed
}

impl DebugOutputSink {
    const ENTRY_SUFFIX: &str = ".gz";

    pub fn new_directory(prefix: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self::Directory(DirectoryOutput::new(prefix)?))
    }

    pub fn new_tarred(tar_gz_path: impl AsRef<Path>) -> io::Result<Self> {
        let tar = Box::new(Mutex::new(TarredOutput::new(tar_gz_path)?));
        Ok(Self::Tarred(tar))
    }

    // Creates file, if needed, and then writes the debug output
    // This helper fn makes it easier to write with-rs and no-rs separately, and
    // avoid creating an unnecessary file
    pub fn output<T>(
        &self, // avoiding &mut so this can be used from many threads
        path: impl AsRef<Path>,
        items: impl Iterator<Item = T>,
    ) -> io::Result<()>
    where
        T: Serialize,
        Self: Sized,
    {
        let mut items = items.peekable();
        if items.peek().is_none() {
            // early return to avoid creating an empty file
            return Ok(());
        }
        let mut gz = GzEncoder::new(vec![], Compression::best());
        for item in items {
            serde_json::to_writer(&mut gz, &item)?;
            writeln!(&mut gz)?;
        }
        let data = gz.finish()?;
        let filename = append_to_filename(path, Self::ENTRY_SUFFIX);
        match self {
            Self::Directory(directory_output) => directory_output.write(&filename, &data),
            Self::Tarred(tarred_output) => tarred_output.lock().unwrap().write(&filename, &data),
        }
    }

    pub fn close(self) -> io::Result<()> {
        match self {
            Self::Directory(_) => Ok(()),
            Self::Tarred(tarred_output) => tarred_output.into_inner().unwrap().close(),
        }
    }

    /// The maximum length the last component of a [`Path`] passed to [`output`](Self::output`).
    pub fn max_filename_len(
        #[allow(unused_variables)] path: impl AsRef<Path>,
    ) -> std::io::Result<usize> {
        #[cfg(unix)]
        let max_name_len =
            nix::unistd::pathconf(path.as_ref(), nix::unistd::PathconfVar::NAME_MAX)?
                .and_then(|m| usize::try_from(m).ok())
                .unwrap_or(255usize)
                .min(255usize); // Sensible cross-platform limit

        #[cfg(windows)]
        let max_name_len = 255usize;

        Ok(max_name_len.saturating_sub(Self::ENTRY_SUFFIX.len()))
    }
}

pub struct DirectoryOutput {
    prefix: PathBuf,
}

impl DirectoryOutput {
    pub fn new(prefix: impl AsRef<Path>) -> io::Result<Self> {
        std::fs::create_dir_all(&prefix)?;
        Ok(Self {
            prefix: prefix.as_ref().to_owned(),
        })
    }

    pub fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let filename = self.prefix.join(path);
        let mut file = File::create_new(filename)?;
        file.write_all(data)?;
        file.flush()
    }
}

pub struct TarredOutput {
    entry_prefix: PathBuf,
    tar: Builder<GzEncoder<BufWriter<File>>>,
    username: Option<String>,
    groupname: Option<String>,
    mtime: Option<u64>,
}

fn effective_username() -> Option<String> {
    #[cfg(unix)]
    let username = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .ok()
        .flatten()
        .map(|u| u.name);

    #[cfg(windows)]
    let username = None;

    username
}

fn effective_groupname() -> Option<String> {
    #[cfg(unix)]
    let groupname = nix::unistd::Group::from_gid(nix::unistd::Gid::effective())
        .ok()
        .flatten()
        .map(|g| g.name);

    #[cfg(windows)]
    let groupname = None;

    groupname
}

impl TarredOutput {
    pub fn new(tar_gz_path: impl AsRef<Path>) -> io::Result<Self> {
        let entry_prefix = tar_gz_path
            .as_ref()
            .file_name()
            .ok_or(io::ErrorKind::InvalidInput)?
            .to_owned()
            .into();
        let filename = append_to_filename(tar_gz_path, ".tar.gz");
        let file = BufWriter::new(File::create_new(&filename)?);
        let gz = GzEncoder::new(file, Compression::best());
        let tar = Builder::new(gz);
        let username = effective_username();
        let groupname = effective_groupname();
        let mtime = UNIX_EPOCH.elapsed().ok().map(|d| d.as_secs());
        // TODO: Maybe store directory if that doesn't need things up front?
        Ok(Self {
            entry_prefix,
            tar,
            username,
            groupname,
            mtime,
        })
    }

    pub fn write(&mut self, path: &Path, data: &[u8]) -> io::Result<()> {
        let data_len = u64::try_from(data.len())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let mut header = self.header();
        header.set_size(data_len);
        header.set_cksum();
        let entry_path = self.entry_prefix.join(path);
        self.tar.append_data(&mut header, entry_path, data)
    }

    fn header(&self) -> Header {
        let mut header = Header::new_gnu();
        header.set_mode(0o644); // rw-r--r--
        if let Some(username) = &self.username {
            let _ = header.set_username(username);
        }
        if let Some(groupname) = &self.groupname {
            let _ = header.set_groupname(groupname);
        }
        if let Some(mtime) = &self.mtime {
            header.set_mtime(*mtime);
        }
        header
    }

    pub fn close(self) -> io::Result<()> {
        self.tar.into_inner()?.finish()?.flush()
    }
}

fn append_to_filename(path: impl AsRef<Path>, ext: impl AsRef<OsStr>) -> PathBuf {
    let path = path.as_ref();
    assert!(path.file_name().is_some());
    let mut os_string = path.as_os_str().to_owned();
    os_string.push(ext);
    os_string.into()
}
