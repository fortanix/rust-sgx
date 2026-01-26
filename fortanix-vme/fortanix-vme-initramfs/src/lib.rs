#![deny(warnings)]
use cpio::{self, NewcReader};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use thiserror::Error;

mod fs_tree;

pub use fs_tree::{FsTree, FsTreeEntry};

const DEFAULT_UID: u32 = 0;
const DEFAULT_GID: u32 = 0;

pub struct Initramfs<R: Read>(R);

#[derive(Error, Debug)]
pub enum Error {
    #[error("Can't extract data from initramfs")]
    ExtractError(#[source] io::Error),
    #[error("Expected trailer in initramfs missing")]
    ExpectedTrailer,
    #[error("Path conversion error: {0}")]
    PathError(String),
    #[error("Reading initramfs failed")]
    ParseError(#[source] io::Error),
    #[error("Reading from initramfs failed")]
    ReadError(#[source] io::Error),
    #[error(
        "Unexpected data in initramfs file {path:?} (found \"{found:?}\", expected \"{expected:?}\")"
    )]
    UnexpectedData {
        path: String,
        found: String,
        expected: String,
    },
    #[error("Creating initramfs failed")]
    WriteError(#[source] io::Error),
    #[error("Invalid entry name (found \"{found:?}\", expected \"{expected:?}\")")]
    WrongEntryName { found: String, expected: String },
    #[error("Unexpected uid (found \"{found:?}\", expected \"{expected:?}\")")]
    WrongUid { found: u32, expected: u32 },
    #[error("Unexpected gid (found \"{found:?}\", expected \"{expected:?}\")")]
    WrongGid { found: u32, expected: u32 },
    #[error("Unexpected mode (found \"{found:?}\", expected \"{expected:?}\")")]
    WrongMode { found: u32, expected: u32 },
}

impl Error {
    pub fn unexpected_data(path: String, found: String, expected: String) -> Self {
        Error::UnexpectedData {
            path,
            found,
            expected,
        }
    }

    pub fn wrong_entry_name(found: String, expected: String) -> Self {
        Error::WrongEntryName { found, expected }
    }

    pub fn wrong_uid(found: u32, expected: u32) -> Self {
        Error::WrongUid { found, expected }
    }

    pub fn wrong_gid(found: u32, expected: u32) -> Self {
        Error::WrongGid { found, expected }
    }

    pub fn wrong_mode(found: u32, expected: u32) -> Self {
        Error::WrongMode { found, expected }
    }
}

pub trait ReadSeek: Read + Seek {}
impl<R: Read + Seek> ReadSeek for R {}

impl<R: Read> From<R> for Initramfs<R> {
    fn from(reader: R) -> Initramfs<R> {
        Initramfs(reader)
    }
}

impl<R: Read + Write> Initramfs<R> {
    pub fn from_fs_tree(fs_tree: FsTree, output: R) -> Result<Initramfs<R>, Error> {
        let encoder = GzEncoder::new(output, Compression::default());
        let inputs = fs_tree.into_cpio_input()?;
        let encoder = cpio::write_cpio(inputs.into_iter(), encoder).map_err(Error::WriteError)?;
        let encoder = encoder.finish().map_err(Error::WriteError)?;
        Ok(Initramfs(encoder))
    }
}

impl<R: Read> Initramfs<R> {
    pub fn verify(self, fs_tree: FsTree) -> Result<(), Error> {
        let decoder = GzDecoder::new(self.0);
        let mut reader = NewcReader::new(decoder).map_err(Error::ReadError)?;

        for fs_entry in fs_tree.0.into_iter() {
            match fs_entry {
                FsTreeEntry::File {
                    path,
                    mode,
                    mut content,
                } => {
                    let path_str = path
                        .as_path()
                        .to_str()
                        .ok_or(Error::PathError(path.display().to_string()))?;
                    Initramfs::verify_entry(&reader, path_str, DEFAULT_UID, DEFAULT_GID, mode)?;

                    // Verify content
                    let mut buf = Vec::new();
                    content.read_to_end(&mut buf).map_err(Error::ReadError)?;
                    Initramfs::verify_entry_content(&mut reader, path_str, &buf)?;
                }
                FsTreeEntry::Directory { path, mode } => {
                    let path_str = path
                        .as_path()
                        .to_str()
                        .ok_or(Error::PathError(path.display().to_string()))?;
                    Initramfs::verify_entry(&reader, path_str, DEFAULT_UID, DEFAULT_GID, mode)?;
                }
            }
            reader = Initramfs::next(reader)?;
        }

        if !reader.entry().is_trailer() {
            return Err(Error::ExpectedTrailer);
        }

        Ok(())
    }

    pub fn read_entry_by_path(self, path: &str) -> Result<Vec<u8>, Error> {
        let normalized = FsTree::normalize_path(path);
        let decoder = GzDecoder::new(self.0);
        let mut reader = NewcReader::new(decoder).map_err(Error::ReadError)?;
        loop {
            let entry = reader.entry();
            if entry.is_trailer() {
                break;
            }

            if Path::new(entry.name()) == normalized.as_path() {
                let content = Initramfs::read_entry_content(&mut reader)?;
                return Ok(content);
            }

            reader = Initramfs::next(reader)?;
        }

        Err(Error::PathError(path.to_owned()))
    }

    fn verify_entry(
        reader: &NewcReader<R>,
        path: &str,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<(), Error> {
        let entry = reader.entry();
        if entry.name() != path {
            return Err(Error::wrong_entry_name(
                entry.name().to_string(),
                path.to_string(),
            ));
        }
        if entry.uid() != uid {
            return Err(Error::wrong_uid(entry.uid(), uid));
        }
        if entry.gid() != gid {
            return Err(Error::wrong_gid(entry.gid(), gid));
        }
        if entry.mode() != mode {
            return Err(Error::wrong_mode(entry.mode(), mode));
        }
        Ok(())
    }

    fn verify_entry_content(
        reader: &mut NewcReader<R>,
        path: &str,
        expected: &[u8],
    ) -> Result<(), Error> {
        let data = Self::read_entry_content(reader)?;
        if data != expected {
            let found = String::from_utf8_lossy(&data).to_string();
            let expected = String::from_utf8_lossy(expected).to_string();
            return Err(Error::unexpected_data(path.to_string(), found, expected));
        }

        Ok(())
    }

    fn read_entry_content(reader: &mut NewcReader<R>) -> Result<Vec<u8>, Error> {
        let mut buf = vec![];
        reader.read_to_end(&mut buf).map_err(Error::ReadError)?;
        Ok(buf)
    }

    fn next(reader: NewcReader<R>) -> Result<NewcReader<R>, Error> {
        reader
            .finish()
            .and_then(|r| NewcReader::new(r))
            .map_err(Error::ReadError)
    }

    pub fn into_inner(self) -> R {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Initramfs, fs_tree::FsTree};
    use hex_literal::hex;
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Seek};

    #[test]
    fn create_and_parse_initramfs() {
        // Creating initramfs
        let app0 = vec![1, 2, 3];
        let init0 = vec![4, 5, 6];
        let nsm0 = vec![7, 8, 9];
        let build_fs_tree = {
            let app0 = app0.clone();
            let init0 = init0.clone();
            let nsm0 = nsm0.clone();
            move || {
                FsTree::new()
                    .add_executable("app", Cursor::new(app0.clone()))
                    .add_executable("init", Cursor::new(init0.clone()))
                    .add_executable("nsm", Cursor::new(nsm0.clone()))
            }
        };

        let fs_tree = build_fs_tree();
        let initramfs: Initramfs<Cursor<Vec<u8>>> =
            Initramfs::<Cursor<Vec<_>>>::from_fs_tree(fs_tree, Cursor::new(Vec::new())).unwrap();
        let initramfs_blob: Vec<u8> = initramfs.into_inner().into_inner();
        assert_eq!(initramfs_blob.len(), 188);
        let sha256 = Sha256::digest(&initramfs_blob);
        assert_eq!(
            sha256[..],
            hex!("07b33a2c4abb76d839912f0dfeade8868cb79b28305c86fdfcf3646c5cf504c3")[..]
        );

        let path_bin_pairs = [("app", app0), ("init", init0), ("nsm", nsm0)];

        // Parse initramfs and verify binaries in it.
        let mut cursor = Cursor::new(initramfs_blob);
        for (path, expected) in path_bin_pairs {
            cursor.rewind().unwrap();
            let bin = Initramfs::from(&mut cursor)
                .read_entry_by_path(path)
                .unwrap();
            assert_eq!(expected, bin, "Binary with path {} is corrupted", path);
        }

        let fs_tree = build_fs_tree();
        cursor.rewind().unwrap();
        let initramfs = Initramfs::from(&mut cursor);
        initramfs.verify(fs_tree).unwrap();
    }
}
