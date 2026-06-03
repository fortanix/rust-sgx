use crate::{Error, ReadSeek, DEFAULT_GID, DEFAULT_UID};
use cpio::NewcBuilder;
use derivative::Derivative;
use normalize_path::NormalizePath;
use std::ffi::OsString;
use std::fmt;
use std::io::Cursor;
use std::path::{Path, PathBuf};

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
pub struct FsTree(pub(crate) Vec<FsTreeEntry>);

type CpioInput = (NewcBuilder, Box<dyn ReadSeek>);

impl FsTree {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn eq_metadata(&self, other: &Self) -> bool {
        self.0.iter().zip(&other.0).all(|(l, r)| l.eq_metadata(r))
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
        self.0
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
        self.0.extend(to_add.into_iter().rev());
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

        self.0.push(entry);
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

        self.0.push(entry);
        self
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
        let mut inputs = Vec::with_capacity(self.0.len());
        for entry in self.0 {
            let input = entry.into_cpio_input()?;
            inputs.push(input);
        }

        Ok(inputs)
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

        let expected = FsTree(vec![
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
        ]);
        assert!(files.eq_metadata(&expected));
    }

    #[test]
    fn test_long_paths() {
        let files = FsTree::new().add_file("a/b/c/d/e/f/g.txt", Cursor::new(vec![]));
        let expected = FsTree(vec![
            make_directory("./a"),
            make_directory("./a/b"),
            make_directory("./a/b/c"),
            make_directory("./a/b/c/d"),
            make_directory("./a/b/c/d/e"),
            make_directory("./a/b/c/d/e/f"),
            make_file("./a/b/c/d/e/f/g.txt", Cursor::new(vec![])),
        ]);
        assert!(files.eq_metadata(&expected));
    }

    #[test]
    fn test_relative_paths() {
        let files = FsTree::new()
            .add_directory("a/b/c/../../d/e/")
            .add_directory("/x/y/../z");
        let expected = FsTree(vec![
            make_directory("./a"),
            make_directory("./a/d"),
            make_directory("./a/d/e"),
            make_directory("./x"),
            make_directory("./x/z"),
        ]);
        assert!(files.eq_metadata(&expected));
    }

    #[test]
    fn test_partial_eq() {
        let entry1 = make_file("/tmp/a.txt", Cursor::new(vec![1, 2, 3, 4]));
        let entry2 = make_file("/tmp/a.txt", Cursor::new(vec![5, 6, 7, 8]));
        assert!(entry1.eq_metadata(&entry2));
    }
}
