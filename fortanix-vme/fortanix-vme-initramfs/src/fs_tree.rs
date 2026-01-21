use crate::{Error, ReadSeek};
use cpio::NewcBuilder;
use std::fmt;
use std::io::Cursor;
use std::path::{Path, PathBuf};

const DEFAULT_FILE_PERMS: u32 = 0o100664;
const DEFAULT_DIR_PERMS: u32 = 0o40775;
const DEFAULT_EXEC_PERMS: u32 = 0o100775;
const REL_TO_CUR: &str = "./";

/// A builder for constructing an [`FsTree`] incrementally.
///
/// `FsTreeBuilder` provides an interface for adding directories and files
/// (including executables) to a filesystem tree. Parent directories are created
/// automatically as needed, and all paths are normalized to be relative to the
/// root of the tree.
///
/// The builder is consumed on each method call and produces a finalized
/// [`FsTree`] when [`build`](Self::build) is invoked.
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
#[derive(Debug, Default)]
pub struct FsTreeBuilder {
    entries: Vec<FsTreeEntry>,
}

impl FsTreeBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add_directory(mut self, dirname: &str) -> FsTreeBuilder {
        let path = Self::normalize_path(dirname);
        self.add_directory_with_parents(path.as_path(), DEFAULT_DIR_PERMS);
        self
    }

    fn dir_exists(&self, dir: &PathBuf) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e, FsTreeEntry::Directory { path, .. } if path == dir))
    }

    fn add_directory_with_parents(&mut self, dir: &Path, mode: u32) {
        let mut to_add = Vec::new();
        for dir in dir.ancestors() {
            if dir == Path::new("") || dir == Path::new(".") {
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
        self.entries.extend(to_add.into_iter().rev());
    }

    pub fn add_executable<T>(self, basename: &str, content: T) -> FsTreeBuilder
    where
        T: ReadSeek + 'static,
    {
        self.add_file_with_permissions(basename, content, DEFAULT_EXEC_PERMS)
    }

    pub fn add_file<T>(self, basename: &str, content: T) -> FsTreeBuilder
    where
        T: ReadSeek + 'static,
    {
        self.add_file_with_permissions(basename, content, DEFAULT_FILE_PERMS)
    }

    pub fn add_file_with_permissions<T>(
        mut self,
        basename: &str,
        content: T,
        mode: u32,
    ) -> FsTreeBuilder
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

        self.entries.push(entry);
        self
    }

    pub fn normalize_path(basename: &str) -> PathBuf {
        // Path in initramfs must relative to the current directory
        // Make sure that given paths does not start with '.', './'
        let mut path = PathBuf::from(REL_TO_CUR);
        if let Some(basename) = basename.strip_prefix("/") {
            path.push(basename);
        } else if let Some(basename) = basename.strip_prefix("./") {
            path.push(basename);
        } else {
            path.push(basename);
        }

        path
    }

    pub fn build(self) -> FsTree {
        FsTree(self.entries)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct FsTree(pub(crate) Vec<FsTreeEntry>);

pub enum FsTreeEntry {
    Directory {
        path: PathBuf,
        mode: u32,
    },
    File {
        path: PathBuf,
        mode: u32,
        content: Box<dyn ReadSeek>,
    },
}

impl fmt::Debug for FsTreeEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsTreeEntry::Directory { path, mode } => f
                .debug_struct("FsTreeEntry::Directory")
                .field("path", path)
                .field("mode", mode)
                .finish(),
            FsTreeEntry::File { path, mode, .. } => f
                .debug_struct("FsTreeEntry::File")
                .field("path", path)
                .field("mode", mode)
                .finish(),
        }
    }
}

impl PartialEq for FsTreeEntry {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                FsTreeEntry::Directory { path: p1, mode: m1 },
                FsTreeEntry::Directory { path: p2, mode: m2 },
            ) => p1 == p2 && m1 == m2,
            (
                FsTreeEntry::File {
                    path: p1, mode: m1, ..
                },
                FsTreeEntry::File {
                    path: p2, mode: m2, ..
                },
            ) => p1 == p2 && m1 == m2,
            _ => false,
        }
    }
}

impl Eq for FsTreeEntry {}

impl FsTreeEntry {
    pub(crate) fn into_cpio_input(self) -> Result<(NewcBuilder, Box<dyn ReadSeek>), Error> {
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
                let buffer = Box::new(content);
                Ok((builder, buffer))
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
    fn test_fstree_builder() {
        let content = vec![0, 1, 2, 3, 4];
        let builder = FsTreeBuilder::new()
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
        let files = builder.build();
        // Note that files is sorted to keep order
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
    fn test_fstree_builder_long() {
        let builder = FsTreeBuilder::new().add_file("a/b/c/d/e/f/g.txt", Cursor::new(vec![]));
        let files = builder.build();
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
}
