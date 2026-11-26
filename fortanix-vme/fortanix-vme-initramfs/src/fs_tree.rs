use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};

use cpio::{newc, NewcBuilder};
use derivative::Derivative;
use normalize_path::NormalizePath;

use crate::{Error, ReadSeek, DEFAULT_GID, DEFAULT_UID};

const DEFAULT_FILE_PERMS: u32 = 0o100664;
const DEFAULT_DIR_PERMS: u32 = 0o40775;
const DEFAULT_EXEC_PERMS: u32 = 0o100775;
pub const DEFAULT_SYMLINK_PERMS: u32 = 0o120777;
const REL_TO_CUR: &str = "./";

/// A builder for constructing an initramfs filesystem [`FsTree`] incrementally.
///
/// `FsTree` provides an interface for adding directories and files
/// (including executables) to a filesystem tree. Parent directories are created
/// automatically as needed, and all paths are normalized to be relative to the
/// root of the tree.
///
/// # Example
///
/// ```text
/// use std::io::Cursor;
///
/// let fs_tree = FsTree::new()
///     .add_directory("bin")
///     .add_executable("bin/init", Cursor::new(b"#!/bin/sh\n"))
///     .add_file("etc/config", Cursor::new(b"key=value\n"))
///     .build();
/// ```
#[derive(Debug, Default)]
pub struct FsTree {
    pub(crate) entries: Vec<FsTreeEntry>,
    pub(crate) hardlink_targets: HashMap<OsString, HardlinkTarget>,
}

type CpioInput = (NewcBuilder, Box<dyn ReadSeek>);

impl FsTree {
    pub fn new() -> Self {
        let entries = Vec::new();
        let hardlink_targets = HashMap::new();
        Self {
            entries,
            hardlink_targets,
        }
    }

    pub fn eq_metadata(&self, other: &Self) -> bool {
        self.entries
            .iter()
            .zip(&other.entries)
            .all(|(l, r)| l.eq_metadata(r))
    }

    pub fn add_directory<P: AsRef<Path>>(self, dirname: P) -> FsTree {
        self.add_directory_with_permissions(dirname, DEFAULT_DIR_PERMS)
    }

    pub fn add_directory_with_permissions<P: AsRef<Path>>(
        mut self,
        dirname: P,
        mode: u32,
    ) -> FsTree {
        let path = Self::normalize_path(dirname);
        self.add_directory_with_parents(path.as_path(), mode);
        self
    }

    fn dir_exists(&self, dir: &Path) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e, FsTreeEntry { path, inner: FsTreeEntryInner::Directory, .. } if path == dir))
    }

    fn add_directory_with_parents(&mut self, dir: &Path, mode: u32) {
        let mut to_add = Vec::new();
        for dir in dir.ancestors() {
            if dir == Path::new(".") {
                break;
            }

            let path_buf = dir.to_path_buf();
            if self.dir_exists(&path_buf) {
                break;
            }

            let dir_entry = FsTreeEntry::dir(path_buf, mode);
            to_add.push(dir_entry);
        }

        // Add in reverse order to preserve the the order of directory
        // hiearchy while adding into initramfs
        self.entries.extend(to_add.into_iter().rev());
    }

    pub fn add_executable<T, P: AsRef<Path>>(self, basename: P, content: T) -> FsTree
    where
        T: ReadSeek + 'static,
    {
        self.add_file_with_permissions(basename, content, DEFAULT_EXEC_PERMS)
    }

    pub fn add_file<T, P: AsRef<Path>>(self, basename: P, content: T) -> FsTree
    where
        T: ReadSeek + 'static,
    {
        self.add_file_with_permissions(basename, content, DEFAULT_FILE_PERMS)
    }

    pub fn add_file_with_permissions<T, P: AsRef<Path>>(
        mut self,
        basename: P,
        content: T,
        mode: u32,
    ) -> FsTree
    where
        T: ReadSeek + 'static,
    {
        let path = Self::normalize_path(basename);

        // Add parents first
        if let Some(parent) = path.parent() {
            self.add_directory_with_parents(parent, DEFAULT_DIR_PERMS);
        }

        let entry = FsTreeEntry::file(path, mode, Box::new(content));

        self.entries.push(entry);
        self
    }

    pub fn add_symlink<P: AsRef<Path>, U: AsRef<Path>>(self, path: P, target: U) -> FsTree {
        self.add_symlink_with_permissions(path, target, DEFAULT_SYMLINK_PERMS)
    }

    pub fn add_symlink_with_permissions<P: AsRef<Path>, U: AsRef<Path>>(
        mut self,
        path: P,
        target: U,
        mode: u32,
    ) -> FsTree {
        let path = Self::normalize_path(path);

        // Add parents first
        if let Some(parent) = path.parent() {
            self.add_directory_with_parents(parent, DEFAULT_DIR_PERMS);
        }

        let entry = FsTreeEntry::symlink(path, mode, target);

        self.entries.push(entry);
        self
    }

    pub fn add_hardlink<P: AsRef<Path>, U: AsRef<Path>>(
        mut self,
        path: P,
        target: U,
    ) -> Result<FsTree, Error> {
        let path = Self::normalize_path(path);
        let target = Self::normalize_path(target).as_os_str().to_os_string();
        if path == target {
            return Err(Error::PathError(format!(
                "Cyclic hardlinks are not allowed, path: {:?}",
                path
            )));
        }

        self.inc_hardlink_target_ref(target.clone());

        if let Some(parent) = path.parent() {
            self.add_directory_with_parents(parent, DEFAULT_DIR_PERMS);
        }

        let entry = FsTreeEntry::hardlink(path, target);

        self.entries.push(entry);
        Ok(self)
    }

    pub fn inc_hardlink_target_ref(&mut self, target: OsString) {
        if let Some(hardlink_target) = self.hardlink_targets.get_mut(&target) {
            hardlink_target.nlink += 1;
        } else {
            let hardlink_target = HardlinkTarget {
                entries_index: None,
                // Start from 2 as hardlink comes with target & source
                nlink: 2,
            };
            self.hardlink_targets.insert(target, hardlink_target);
        }
    }

    /// Normalizes a path and anchors it to the current working directory.
    ///
    /// This function performs standard path normalization, removes any leading
    /// absolute root separators (`/`), and prepends the internal `./`
    /// prefix to ensure the path is relative for the initramfs environment.
    pub(crate) fn normalize_path<P: AsRef<Path>>(basename: P) -> PathBuf {
        // Do the regular normalization first
        let normalized = basename.as_ref().normalize();
        // Normalized path may begin with "/", drop it if exists
        let stripped = if let Ok(stripped) = normalized.strip_prefix("/") {
            stripped
        } else {
            &normalized
        };

        // Path in initramfs must be relative to the current directory.
        let mut path = PathBuf::from(REL_TO_CUR);
        path.push(stripped);
        path
    }

    pub fn into_cpio_input(self) -> Result<Vec<CpioInput>, Error> {
        let mut inputs = Vec::with_capacity(self.entries.len());
        for entry in self.entries {
            let input = entry.into_cpio_input()?;
            inputs.push(input);
        }

        Ok(inputs)
    }

    // This is re-write of cpio's `write_cpio function`.
    // Ref: https://github.com/jcreekmore/cpio-rs/blob/0ef80dc848c03dedb24cd5f69fcb37a31e0bbb99/src/lib.rs#L16
    // The re-write is necessary due to the issue:
    // https://github.com/jcreekmore/cpio-rs/issues/23
    //
    // Theory of operation:
    // We first write everything non-hardlink
    // During write, hardlink target indexes are resolved
    // As a last step hardlink sources are written
    // by using resolved hardlink target indexes
    pub fn write_cpio<W: Write>(mut self, mut output: W) -> Result<W, Error> {
        let mut hardlink_entries = Vec::new();
        let mut inode_mode_pairs = vec![(0, 0); self.entries.len()];
        for (index, entry) in self.entries.into_iter().enumerate() {
            if matches!(entry.inner, FsTreeEntryInner::Hardlink { .. }) {
                hardlink_entries.push(entry);
                continue;
            }

            let mut nlink = 1;
            if matches!(entry.inner, FsTreeEntryInner::File { .. }) {
                let path = entry.path.as_os_str();
                if let Some(hardlink_entry) = self.hardlink_targets.get_mut(path) {
                    hardlink_entry.entries_index = Some(index);
                    nlink = hardlink_entry.nlink;
                }
            }

            let inode = index as u32;
            inode_mode_pairs[index] = (inode, entry.mode);
            Self::write_cpio_entry(entry, inode, nlink, &mut output)?;
        }

        for mut entry in hardlink_entries {
            let FsTreeEntry {
                path,
                mode: _,
                inner: FsTreeEntryInner::Hardlink { target },
            } = &entry
            else {
                // This list is only populated with hardlink entries above
                unreachable!();
            };
            let (entry_index, nlink) =
                if let Some(hardlink_entry) = self.hardlink_targets.get(target) {
                    (hardlink_entry.entries_index, hardlink_entry.nlink)
                } else {
                    (None, 0)
                };
            let entry_index =
                entry_index.ok_or(Error::missing_hardlink_target(path.as_os_str(), target))?;
            let (inode, mode) = inode_mode_pairs[entry_index];
            // Update entry mode based on link target.
            entry.mode = mode;
            Self::write_cpio_entry(entry, inode, nlink, &mut output)?;
        }

        newc::trailer(output).map_err(Error::WriteError)
    }

    fn write_cpio_entry<W: Write>(
        entry: FsTreeEntry,
        inode: u32,
        nlink: u32,
        output: &mut W,
    ) -> Result<(), Error> {
        let (builder, mut input) = entry.into_cpio_input()?;
        let len = input.seek(io::SeekFrom::End(0)).map_err(Error::ReadError)?;
        input
            .seek(io::SeekFrom::Start(0))
            .map_err(Error::WriteError)?;

        let mut fp = builder.ino(inode).nlink(nlink).write(output, len as u32);
        io::copy(&mut input, &mut fp).map_err(Error::WriteError)?;
        fp.finish().map_err(Error::WriteError)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct FsTreeEntry {
    pub path: PathBuf,
    pub mode: u32,
    pub inner: FsTreeEntryInner,
}

impl FsTreeEntry {
    pub fn dir<P: AsRef<Path>>(path: P, mode: u32) -> Self {
        let path = path.as_ref().to_path_buf();

        Self {
            path,
            mode,
            inner: FsTreeEntryInner::Directory,
        }
    }

    pub fn file<P: AsRef<Path>>(path: P, mode: u32, content: Box<dyn ReadSeek>) -> Self {
        let path = path.as_ref().to_path_buf();

        Self {
            path,
            mode,
            inner: FsTreeEntryInner::File { content },
        }
    }

    pub fn symlink<P: AsRef<Path>, U: AsRef<Path>>(path: P, mode: u32, target: U) -> Self {
        let path = path.as_ref().to_path_buf();
        let target = target.as_ref().into();

        Self {
            path,
            mode,
            inner: FsTreeEntryInner::Symlink { target },
        }
    }

    pub fn hardlink<P: AsRef<Path>>(path: P, target: OsString) -> Self {
        let path = path.as_ref().to_path_buf();
        let mode = 0; // The target file's mode overrides after resolution
        Self {
            path,
            mode,
            inner: FsTreeEntryInner::Hardlink { target },
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub enum FsTreeEntryInner {
    Directory,
    File {
        #[derivative(Debug(format_with = "redact"))]
        content: Box<dyn ReadSeek>,
    },
    Symlink {
        target: OsString,
    },
    Hardlink {
        target: OsString,
    },
}

#[derive(Debug)]
pub(crate) struct HardlinkTarget {
    entries_index: Option<usize>,
    nlink: u32,
}

fn redact<T>(_: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "...")
}

impl FsTreeEntry {
    pub(crate) fn into_cpio_input(self) -> Result<CpioInput, Error> {
        let builder = self.get_newcbuilder()?;
        let content = match self.inner {
            FsTreeEntryInner::Directory => Box::new(Cursor::new([] as [u8; 0])),
            FsTreeEntryInner::File { content } => content,
            FsTreeEntryInner::Symlink { target } => {
                Box::new(Cursor::new(target.into_encoded_bytes()))
            }
            FsTreeEntryInner::Hardlink { .. } => Box::new(Cursor::new([] as [u8; 0])),
        };
        Ok((builder, content))
    }

    fn get_newcbuilder(&self) -> Result<NewcBuilder, Error> {
        let name = self
            .path
            .to_str()
            .ok_or(Error::PathError(format!("{}", self.path.display())))?;
        Ok(NewcBuilder::new(name)
            .uid(DEFAULT_UID)
            .gid(DEFAULT_GID)
            .mode(self.mode))
    }

    /// Compares the metadata of two entries while ignoring the file content.
    ///
    /// Returns `true` if both entries are of the same type (both files or both directories)
    /// and their `path` and `mode` are identical.
    pub fn eq_metadata(&self, other: &Self) -> bool {
        let FsTreeEntry {
            path: p1,
            mode: m1,
            inner: inner1,
        } = self;
        let FsTreeEntry {
            path: p2,
            mode: m2,
            inner: inner2,
        } = other;
        match (inner1, inner2) {
            (FsTreeEntryInner::Directory, FsTreeEntryInner::Directory) => p1 == p2 && m1 == m2,
            (FsTreeEntryInner::File { .. }, FsTreeEntryInner::File { .. }) => p1 == p2 && m1 == m2,
            (
                FsTreeEntryInner::Symlink { target: t1 },
                FsTreeEntryInner::Symlink { target: t2 },
            ) => p1 == p2 && t1 == t2 && m1 == m2,
            (
                FsTreeEntryInner::Hardlink { target: t1 },
                FsTreeEntryInner::Hardlink { target: t2 },
            ) => p1 == p2 && t1 == t2 && m1 == m2,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file<T: ReadSeek + 'static>(path: &str, content: T) -> FsTreeEntry {
        FsTreeEntry::file(PathBuf::from(path), DEFAULT_FILE_PERMS, Box::new(content))
    }

    fn make_directory(path: &str) -> FsTreeEntry {
        FsTreeEntry::dir(PathBuf::from(path), DEFAULT_DIR_PERMS)
    }

    fn make_symlink(path: &str, target: &str) -> FsTreeEntry {
        FsTreeEntry::symlink(
            PathBuf::from(path),
            DEFAULT_SYMLINK_PERMS,
            target.to_owned(),
        )
    }

    #[test]
    fn test_structure() {
        let content = vec![0, 1, 2, 3, 4];
        let files = FsTree::new()
            .add_file("rootfs/bin/a.out", Cursor::new(content.clone()))
            .add_directory("rootfs/dev")
            .add_directory("rootfs/proc")
            .add_directory("rootfs/run")
            .add_directory("rootfs/sys")
            .add_directory("rootfs/tmp")
            .add_file("cmd", Cursor::new(content.clone()))
            .add_file("env", Cursor::new(content.clone()))
            .add_file("init", Cursor::new(content.clone()))
            .add_file("nsm.ko", Cursor::new(content.clone()))
            .add_symlink("rootfs/bin/sh", "dash");

        let mut expected = FsTree::new();
        expected.entries = vec![
            make_directory("./rootfs"),
            make_directory("./rootfs/bin"),
            make_file("./rootfs/bin/a.out", Cursor::new(content.clone())),
            make_directory("./rootfs/dev"),
            make_directory("./rootfs/proc"),
            make_directory("./rootfs/run"),
            make_directory("./rootfs/sys"),
            make_directory("./rootfs/tmp"),
            make_file("./cmd", Cursor::new(content.clone())),
            make_file("./env", Cursor::new(content.clone())),
            make_file("./init", Cursor::new(content.clone())),
            make_file("./nsm.ko", Cursor::new(content.clone())),
            make_symlink("./rootfs/bin/sh", "dash"),
        ];
        assert!(files.eq_metadata(&expected));
    }

    #[test]
    fn test_long_paths() {
        let files = FsTree::new().add_file("a/b/c/d/e/f/g.txt", Cursor::new(vec![]));
        let mut expected = FsTree::new();
        expected.entries = vec![
            make_directory("./a"),
            make_directory("./a/b"),
            make_directory("./a/b/c"),
            make_directory("./a/b/c/d"),
            make_directory("./a/b/c/d/e"),
            make_directory("./a/b/c/d/e/f"),
            make_file("./a/b/c/d/e/f/g.txt", Cursor::new(vec![])),
        ];
        assert!(files.eq_metadata(&expected));
    }

    #[test]
    fn test_relative_paths() {
        let files = FsTree::new()
            .add_directory("a/b/c/../../d/e/")
            .add_directory("/x/y/../z");
        let mut expected = FsTree::new();
        expected.entries = vec![
            make_directory("./a"),
            make_directory("./a/d"),
            make_directory("./a/d/e"),
            make_directory("./x"),
            make_directory("./x/z"),
        ];
        assert!(files.eq_metadata(&expected));
    }

    #[test]
    fn test_partial_eq() {
        let entry1 = make_file("/tmp/a.txt", Cursor::new(vec![1, 2, 3, 4]));
        let entry2 = make_file("/tmp/a.txt", Cursor::new(vec![5, 6, 7, 8]));
        assert!(entry1.eq_metadata(&entry2));
    }
}
