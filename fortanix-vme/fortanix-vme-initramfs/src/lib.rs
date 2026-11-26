#![deny(warnings)]
use cpio::{self, NewcReader};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use thiserror::Error;

mod fs_tree;

pub use fs_tree::{FsTree, FsTreeEntry, FsTreeEntryInner, DEFAULT_SYMLINK_PERMS};

const DEFAULT_UID: u32 = 0;
const DEFAULT_GID: u32 = 0;

pub struct Initramfs<R: Read>(R);

#[derive(Error, Debug)]
pub enum Error {
    #[error("Can't extract data from initramfs")]
    ExtractError(#[source] io::Error),
    #[error("Expected trailer in initramfs missing")]
    ExpectedTrailer,
    #[error("Missing hardlink target: {target:?}, source: {source_:?}")]
    MissingHardlinkTarget { source_: String, target: String },
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
    #[error("Unexpected link count (found {found}, expected {expected})")]
    WrongNlink { found: u32, expected: u32 },
    #[error("Hardlink {source_:?} does not share an inode and device with {target:?}")]
    WrongHardlinkTarget { source_: String, target: String },
}

impl Error {
    pub fn missing_hardlink_target(source: &OsStr, target: &OsStr) -> Self {
        Error::MissingHardlinkTarget {
            source_: format!("{:?}", source),
            target: format!("{:?}", target),
        }
    }

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
        let encoder = fs_tree.write_cpio(encoder)?;
        let encoder = encoder.finish().map_err(Error::WriteError)?;
        Ok(Initramfs(encoder))
    }
}

impl<R: Read> Initramfs<R> {
    pub fn verify(self, fs_tree: FsTree) -> Result<(), Error> {
        let decoder = GzDecoder::new(self.0);
        let mut reader = NewcReader::new(decoder).map_err(Error::ReadError)?;

        // Match the writer's order: regular entries first, then hardlinks.
        let (hardlinks, entries): (Vec<_>, Vec<_>) = fs_tree
            .entries
            .into_iter()
            .partition(|entry| matches!(entry.inner, FsTreeEntryInner::Hardlink { .. }));
        let mut link_counts = HashMap::new();
        for entry in &hardlinks {
            if let FsTreeEntryInner::Hardlink { target } = &entry.inner {
                *link_counts.entry(target.clone()).or_insert(1) += 1;
            }
        }
        let mut targets = HashMap::new();

        for fs_entry in entries.into_iter().chain(hardlinks) {
            let (mode, nlink) = match &fs_entry.inner {
                FsTreeEntryInner::Hardlink { target } => {
                    let &(mode, _, _, _) = targets.get(target).ok_or_else(|| {
                        Error::missing_hardlink_target(fs_entry.path.as_os_str(), target)
                    })?;
                    (mode, link_counts[target])
                }
                FsTreeEntryInner::File { .. } => (
                    fs_entry.mode,
                    link_counts
                        .get(fs_entry.path.as_os_str())
                        .copied()
                        .unwrap_or(1),
                ),
                _ => (fs_entry.mode, 1),
            };
            let path = fs_entry.path;

            Initramfs::verify_entry(&reader, &path, DEFAULT_UID, DEFAULT_GID, mode)?;
            if reader.entry().nlink() != nlink {
                return Err(Error::WrongNlink {
                    found: reader.entry().nlink(),
                    expected: nlink,
                });
            }
            match fs_entry.inner {
                FsTreeEntryInner::File { mut content } => {
                    let entry = reader.entry();
                    targets.insert(
                        path.as_os_str().to_os_string(),
                        (mode, entry.ino(), entry.dev_major(), entry.dev_minor()),
                    );
                    // Verify content
                    let mut buf = Vec::new();
                    content.read_to_end(&mut buf).map_err(Error::ReadError)?;
                    Initramfs::verify_entry_content(&mut reader, &path, &buf)?;
                }
                FsTreeEntryInner::Directory => {
                    // No content to verify
                }
                FsTreeEntryInner::Symlink { target } => {
                    // Verify content (target)
                    Initramfs::verify_entry_content(
                        &mut reader,
                        &path,
                        &target.into_encoded_bytes(),
                    )?;
                }
                FsTreeEntryInner::Hardlink { target } => {
                    let &(_, ino, dev_major, dev_minor) = &targets[&target];
                    let entry = reader.entry();
                    if (entry.ino(), entry.dev_major(), entry.dev_minor())
                        != (ino, dev_major, dev_minor)
                    {
                        return Err(Error::WrongHardlinkTarget {
                            source_: path.display().to_string(),
                            target: target.to_string_lossy().into_owned(),
                        });
                    }
                    Initramfs::verify_entry_content(&mut reader, &path, &[])?;
                }
            }
            reader = Initramfs::next(reader)?;
        }

        if !reader.entry().is_trailer() {
            return Err(Error::ExpectedTrailer);
        }

        Ok(())
    }

    pub fn read_entry_by_path<P: AsRef<Path>>(self, path: P) -> Result<Vec<u8>, Error> {
        let normalized = FsTree::normalize_path(path.as_ref());
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

        Err(Error::PathError(format!("{}", path.as_ref().display())))
    }

    fn verify_entry(
        reader: &NewcReader<R>,
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<(), Error> {
        let entry = reader.entry();

        if entry.name() != path {
            return Err(Error::wrong_entry_name(
                entry.name().to_string(),
                format!("{}", path.display()),
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
        path: &Path,
        expected: &[u8],
    ) -> Result<(), Error> {
        let data = Self::read_entry_content(reader)?;
        if data != expected {
            let found = String::from_utf8_lossy(&data).to_string();
            let expected = String::from_utf8_lossy(expected).to_string();

            return Err(Error::unexpected_data(
                format!("{}", path.display()),
                found,
                expected,
            ));
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
    use super::{fs_tree::FsTree, Error, Initramfs};
    use cpio::NewcBuilder;
    use flate2::{write::GzEncoder, Compression};
    use hex_literal::hex;
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Seek};

    fn hardlink_tree() -> FsTree {
        FsTree::new()
            .add_hardlink("alias", "target")
            .unwrap()
            .add_executable("target", Cursor::new(b"payload"))
            .add_hardlink("alias2", "target")
            .unwrap()
    }

    #[test]
    fn verify_hardlinks_before_and_after_target() {
        let archive = Initramfs::from_fs_tree(hardlink_tree(), Cursor::new(Vec::new())).unwrap();
        let mut data = archive.into_inner();
        data.rewind().unwrap();
        Initramfs::from(data).verify(hardlink_tree()).unwrap();
    }

    // Build independent archive fixtures so FsTree::verify is tested against malformed headers
    fn hardlink_fixture(alias: NewcBuilder, content: &[u8], target_nlink: u32) -> Cursor<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        let entries = [
            (
                NewcBuilder::new("./target")
                    .mode(0o100775)
                    .ino(7)
                    .nlink(target_nlink),
                &b"payload"[..],
            ),
            (alias, content),
            (
                NewcBuilder::new("./alias2").mode(0o100775).ino(7).nlink(3),
                &b""[..],
            ),
        ];
        for (builder, mut content) in entries {
            let mut writer = builder.write(&mut encoder, content.len() as u32);
            std::io::copy(&mut content, &mut writer).unwrap();
            writer.finish().unwrap();
        }
        cpio::newc::trailer(&mut encoder).unwrap();
        Cursor::new(encoder.finish().unwrap())
    }

    fn alias_builder() -> NewcBuilder {
        NewcBuilder::new("./alias").mode(0o100775).ino(7).nlink(3)
    }

    #[test]
    fn verify_hardlinks_accepts_independent_inode_numbers() {
        Initramfs::from(hardlink_fixture(alias_builder(), b"", 3))
            .verify(hardlink_tree())
            .unwrap();
    }

    #[test]
    fn verify_hardlinks_rejects_wrong_inode_or_device() {
        for alias in [
            alias_builder().ino(8),
            alias_builder().dev_major(1),
            alias_builder().dev_minor(1),
        ] {
            assert!(matches!(
                Initramfs::from(hardlink_fixture(alias, b"", 3)).verify(hardlink_tree()),
                Err(Error::WrongHardlinkTarget { .. })
            ));
        }
    }

    #[test]
    fn verify_hardlinks_rejects_wrong_link_counts() {
        for (alias, target_nlink) in [(alias_builder().nlink(2), 3), (alias_builder(), 1)] {
            assert!(matches!(
                Initramfs::from(hardlink_fixture(alias, b"", target_nlink)).verify(hardlink_tree()),
                Err(Error::WrongNlink { .. })
            ));
        }
    }

    #[test]
    fn verify_hardlinks_rejects_wrong_mode_and_content() {
        assert!(matches!(
            Initramfs::from(hardlink_fixture(alias_builder().mode(0o100664), b"", 3))
                .verify(hardlink_tree()),
            Err(Error::WrongMode { .. })
        ));
        assert!(matches!(
            Initramfs::from(hardlink_fixture(alias_builder(), b"extra", 3)).verify(hardlink_tree()),
            Err(Error::UnexpectedData { .. })
        ));
    }

    #[test]
    fn verify_hardlinks_reports_missing_target() {
        let archive = Initramfs::from_fs_tree(FsTree::new(), Cursor::new(Vec::new())).unwrap();
        let mut data = archive.into_inner();
        data.rewind().unwrap();
        let expected = FsTree::new().add_hardlink("alias", "missing").unwrap();
        assert!(matches!(
            Initramfs::from(data).verify(expected),
            Err(Error::MissingHardlinkTarget { .. })
        ));
    }

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
                    .add_symlink("sh", "app")
            }
        };

        let fs_tree = build_fs_tree();
        let initramfs: Initramfs<Cursor<Vec<u8>>> =
            Initramfs::<Cursor<Vec<_>>>::from_fs_tree(fs_tree, Cursor::new(Vec::new())).unwrap();
        let initramfs_blob: Vec<u8> = initramfs.into_inner().into_inner();
        assert_eq!(initramfs_blob.len(), 229);
        let sha256 = Sha256::digest(&initramfs_blob);
        assert_eq!(
            sha256[..],
            hex!("1288d75f2b03df145219cb7d1d966fbaaeedd0ca352cb3971fca4d36ca269147")[..]
        );

        let path_bin_pairs = [
            ("app", app0),
            ("init", init0),
            ("nsm", nsm0),
            ("sh", b"app".to_vec()),
        ];

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
