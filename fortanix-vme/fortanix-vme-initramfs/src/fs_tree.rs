use crate::{Error, ReadSeek};
use cpio::NewcBuilder;
use derivative::Derivative;
use normalize_path::NormalizePath;
use std::fmt;
use std::io::Cursor;
use std::path::{Path, PathBuf};

const DEFAULT_FILE_PERMS: u32 = 0o100664;
const DEFAULT_DIR_PERMS: u32 = 0o40775;
const DEFAULT_EXEC_PERMS: u32 = 0o100775;
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
/// let fs_tree = FsTreeBuilder::new()
///     .add_directory("bin")
///     .add_executable("bin/init", Cursor::new(b"#!/bin/sh\n"))
///     .add_file("etc/config", Cursor::new(b"key=value\n"))
///     .build();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct FsTree(pub(crate) Vec<FsTreeEntry>);

type CpioInput = (NewcBuilder, Box<dyn ReadSeek>);

impl FsTree {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add_directory(mut self, dirname: &str) -> FsTree {
        let path = Self::normalize_path(dirname);
        self.add_directory_with_parents(path.as_path(), DEFAULT_DIR_PERMS);
        self
    }

    fn dir_exists(&self, dir: &PathBuf) -> bool {
        self.0
            .iter()
            .any(|e| matches!(e, FsTreeEntry::Directory { path, .. } if path == dir))
    }

    fn add_directory_with_parents(&mut self, dir: &Path, mode: u32) {
        let mut to_add = Vec::new();
        for dir in dir.ancestors() {
            if dir == Path::new(".") {
                break;
            }

            let path_buf = dir.into();
            if self.dir_exists(&path_buf) {
                break;
            }

            to_add.push(FsTreeEntry::Directory {
                path: path_buf,
                mode,
            });
        }

        // Add in reverse order to preserve the the order of directory
        // hiearchy while adding into initramfs
        self.0.extend(to_add.into_iter().rev());
    }

    pub fn add_executable<T>(self, basename: &str, content: T) -> FsTree
    where
        T: ReadSeek + 'static,
    {
        self.add_file_with_permissions(basename, content, DEFAULT_EXEC_PERMS)
    }

    pub fn add_file<T>(self, basename: &str, content: T) -> FsTree
    where
        T: ReadSeek + 'static,
    {
        self.add_file_with_permissions(basename, content, DEFAULT_FILE_PERMS)
    }

    pub fn add_file_with_permissions<T>(mut self, basename: &str, content: T, mode: u32) -> FsTree
    where
        T: ReadSeek + 'static,
    {
        let mut path = Self::normalize_path(basename);
        let entry = FsTreeEntry::File {
            path: path.clone(),
            mode,
            content: Box::new(content),
        };

        // Add parents first
        if path.pop() {
            self.add_directory_with_parents(path.as_path(), DEFAULT_DIR_PERMS);
        }

        self.0.push(entry);
        self
    }

    /// Normalizes a path and anchors it to the current working directory.
    ///
    /// This function performs standard path normalization, removes any leading
    /// absolute root separators (`/`), and prepends the internal `./`
    /// prefix to ensure the path is relative for the initramfs environment.
    pub(crate) fn normalize_path(basename: &str) -> PathBuf {
        // Do the regular normalization first
        let normalized = Path::new(basename).normalize();
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

#[derive(Derivative)]
#[derivative(Debug, PartialEq)]
pub enum FsTreeEntry {
    Directory {
        path: PathBuf,
        mode: u32,
    },
    File {
        path: PathBuf,
        mode: u32,
        #[derivative(Debug(format_with = "redact"))]
        #[derivative(PartialEq = "ignore")]
        content: Box<dyn ReadSeek>,
    },
}

fn redact<T>(_: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "...")
}

impl Eq for FsTreeEntry {}

impl FsTreeEntry {
    pub(crate) fn into_cpio_input(self) -> Result<CpioInput, Error> {
        match self {
            FsTreeEntry::Directory { path, mode } => {
                let name = path
                    .to_str()
                    .ok_or(Error::PathError(path.display().to_string()))?;
                let builder = NewcBuilder::new(name).uid(0).gid(0).mode(mode);
                let buffer = Box::new(Cursor::new([] as [u8; 0]));
                Ok((builder, buffer))
            }
            FsTreeEntry::File {
                path,
                mode,
                content,
            } => {
                let name = path
                    .to_str()
                    .ok_or(Error::PathError(path.display().to_string()))?;
                let builder = NewcBuilder::new(name).uid(0).gid(0).mode(mode);
                Ok((builder, content))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file<T: ReadSeek + 'static>(path: &str, content: T) -> FsTreeEntry {
        FsTreeEntry::File {
            path: PathBuf::from(path),
            mode: DEFAULT_FILE_PERMS,
            content: Box::new(content),
        }
    }

    fn make_directory(path: &str) -> FsTreeEntry {
        FsTreeEntry::Directory {
            path: PathBuf::from(path),
            mode: DEFAULT_DIR_PERMS,
        }
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
            .add_file("nsm.ko", Cursor::new(content.clone()));

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
        ]);
        assert_eq!(files, expected);
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
        assert_eq!(files, expected);
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
        assert_eq!(files, expected);
    }

    #[test]
    fn test_partial_eq() {
        let entry1 = make_file("/tmp/a.txt", Cursor::new(vec![1, 2, 3, 4]));
        let entry2 = make_file("/tmp/a.txt", Cursor::new(vec![5, 6, 7, 8]));
        assert_eq!(entry1, entry2);
    }
}
