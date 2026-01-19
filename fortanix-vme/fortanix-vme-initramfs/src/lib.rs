#![deny(warnings)]
use cpio::{self, NewcBuilder, NewcReader};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::{self, Cursor, Read, Seek, Write};
use thiserror::Error;

pub struct Initramfs<R: Read>(R);

#[derive(Error, Debug)]
pub enum Error {
    #[error("Can't extract data from initramfs: {0}")]
    ExtractError(#[source] io::Error),
    #[error("Expected trailer in initramfs missing")]
    ExpectedTrailer,
    #[error("Reading initramfs failed: {0}")]
    ParseError(#[source] io::Error),
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

/// A builder to create a gzipped cpio archive of an initramfs suitable to create an AWS Nitro
/// Enclave from.
pub struct Builder<R: Read + Seek + 'static, S: Read + Seek + 'static, T: Read + Seek + 'static> {
    application: R,
    init: S,
    nsm: T,
}

trait ReadSeek: Read + Seek {}
impl<R: Read + Seek> ReadSeek for R {}

impl<R: Read + Seek + 'static, S: Read + Seek + 'static, T: Read + Seek + 'static>
    Builder<R, S, T>
{
    pub fn new(application: R, init: S, nsm: T) -> Self {
        Builder {
            application,
            init,
            nsm,
        }
    }

    fn build_initramfs<U: Read + Write>(self, output: U) -> Result<U, Error> {
        fn directory(path: &str) -> (NewcBuilder, Box<dyn ReadSeek>) {
            (
                NewcBuilder::new(path).uid(0).gid(0).mode(0o40775),
                Box::new(Cursor::new([] as [u8; 0])),
            )
        }

        fn cmd(path: &str) -> (NewcBuilder, Box<dyn ReadSeek>) {
            (
                NewcBuilder::new(path).uid(0).gid(0).mode(0o100664),
                Box::new(Cursor::new(Initramfs::<&[u8]>::CMD.as_bytes())),
            )
        }

        fn env(path: &str) -> (NewcBuilder, Box<dyn ReadSeek>) {
            (
                NewcBuilder::new(path).uid(0).gid(0).mode(0o100664),
                Box::new(Cursor::new(Initramfs::<&[u8]>::ENV.as_bytes())),
            )
        }

        fn executable<RS: ReadSeek + 'static>(
            path: &str,
            exec: RS,
        ) -> (NewcBuilder, Box<dyn ReadSeek>) {
            (
                NewcBuilder::new(path).uid(0).gid(0).mode(0o100775),
                Box::new(exec) as Box<dyn ReadSeek>,
            )
        }

        let Self {
            application,
            init,
            nsm,
        } = self;
        let mut inputs = vec![
            directory("./rootfs"),
            directory("./rootfs/bin"),
            executable("./rootfs/bin/a.out", application),
            directory("./rootfs/dev"),
            directory("./rootfs/proc"),
            directory("./rootfs/run"),
            directory("./rootfs/sys"),
            directory("./rootfs/tmp"),
            cmd("./cmd"),
            env("./env"),
            executable("./init", init),
            executable("./nsm.ko", nsm),
        ];

        cpio::write_cpio(inputs.drain(..), output).map_err(Error::WriteError)
    }

    pub fn build<U: Read + Write>(self, output: U) -> Result<Initramfs<U>, Error> {
        let encoder = GzEncoder::new(output, Compression::default());
        let encoder = self.build_initramfs(encoder)?;
        let encoder = encoder.finish().map_err(Error::WriteError)?;
        Ok(Initramfs(encoder))
    }
}

impl<R: Read> From<R> for Initramfs<R> {
    fn from(reader: R) -> Initramfs<R> {
        Initramfs(reader)
    }
}

impl<R: Read> Initramfs<R> {
    const CMD: &'static str = "/bin/a.out";
    const ENV: &'static str = "";

    pub fn application<T: Write>(self, output: &mut T) -> Result<(), Error> {
        fn check_entry<R: Read>(
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
            if entry.uid() != 0 {
                return Err(Error::wrong_uid(entry.uid(), uid));
            }
            if entry.gid() != 0 {
                return Err(Error::wrong_gid(entry.gid(), gid));
            }
            if entry.mode() != mode {
                return Err(Error::wrong_mode(entry.mode(), mode));
            }
            Ok(())
        }

        fn is_directory<R: Read>(reader: &NewcReader<R>, path: &str) -> Result<(), Error> {
            check_entry(reader, path, 0, 0, 0o40775)
        }

        fn is_executable<R: Read>(reader: &NewcReader<R>, path: &str) -> Result<(), Error> {
            check_entry(reader, path, 0, 0, 0o100775)
        }

        fn is_data<R: Read>(
            reader: &mut NewcReader<R>,
            path: &str,
            content: &str,
        ) -> Result<(), Error> {
            check_entry(reader, path, 0, 0, 0o100664)?;
            let mut data = String::new();
            reader
                .read_to_string(&mut data)
                .map_err(Error::ParseError)?;
            if data != content {
                return Err(Error::unexpected_data(
                    path.to_string(),
                    data,
                    content.to_string(),
                ));
            }
            Ok(())
        }

        fn is_cmd<R: Read>(reader: &mut NewcReader<R>, path: &str) -> Result<(), Error> {
            check_entry(reader, path, 0, 0, 0o100664)?;
            is_data(reader, path, Initramfs::<&[u8]>::CMD)
        }

        fn is_env<R: Read>(reader: &mut NewcReader<R>, path: &str) -> Result<(), Error> {
            check_entry(reader, path, 0, 0, 0o100664)?;
            is_data(reader, path, Initramfs::<&[u8]>::ENV)
        }

        fn is_init<R: Read>(reader: &NewcReader<R>) -> Result<(), Error> {
            is_executable(reader, "./init")
        }

        fn is_nsm<R: Read>(reader: &NewcReader<R>) -> Result<(), Error> {
            is_executable(reader, "./nsm.ko")
        }

        fn next<R: Read>(reader: NewcReader<R>) -> Result<NewcReader<R>, Error> {
            reader
                .finish()
                .and_then(|r| NewcReader::new(r))
                .map_err(Error::WriteError)
        }

        let decoder = GzDecoder::new(self.0);
        let reader = NewcReader::new(decoder).map_err(Error::WriteError)?;
        is_directory(&reader, "./rootfs")?;

        let reader = next(reader)?;
        is_directory(&reader, "./rootfs/bin")?;

        let mut reader = next(reader)?;
        is_executable(&reader, "./rootfs/bin/a.out")?;
        io::copy(&mut reader, output).map_err(Error::ExtractError)?;

        let reader = next(reader)?;
        is_directory(&reader, "./rootfs/dev")?;

        let reader = next(reader)?;
        is_directory(&reader, "./rootfs/proc")?;

        let reader = next(reader)?;
        is_directory(&reader, "./rootfs/run")?;

        let reader = next(reader)?;
        is_directory(&reader, "./rootfs/sys")?;

        let reader = next(reader)?;
        is_directory(&reader, "./rootfs/tmp")?;

        let mut reader = next(reader)?;
        is_cmd(&mut reader, "./cmd")?;

        let mut reader = next(reader)?;
        is_env(&mut reader, "./env")?;

        let reader = next(reader)?;
        is_init(&reader)?;

        let reader = next(reader)?;
        is_nsm(&reader)?;

        let reader = next(reader)?;
        if !reader.entry().is_trailer() {
            return Err(Error::ExpectedTrailer);
        }

        Ok(())
    }

    pub fn into_inner(self) -> R {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Builder, Initramfs};
    use hex_literal::hex;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

    #[test]
    fn create_and_parse_initramfs() {
        // Creating initramfs
        let app0 = vec![1, 2, 3];
        let init = vec![4, 5, 6];
        let nsm = vec![7, 8, 9];
        let builder = Builder::new(
            Cursor::new(app0.clone()),
            Cursor::new(init.clone()),
            Cursor::new(nsm.clone()),
        );
        let initramfs: Initramfs<Cursor<Vec<u8>>> = builder.build(Cursor::new(Vec::new())).unwrap();
        let initramfs: Vec<u8> = initramfs.into_inner().into_inner();
        assert_eq!(initramfs.len(), 334);
        let sha256 = Sha256::digest(&initramfs);
        assert_eq!(
            sha256[..],
            hex!("620fb38c8cc8dccca346dc186431758db60dc7cc8bafb21d7f7b2661ac4775c7")[..]
        );

        // Parsing initramfs
        let initramfs = Initramfs::from(Cursor::new(initramfs));
        let mut app1 = Vec::new();
        initramfs.application(&mut app1).unwrap();
        assert_eq!(app0, app1);
    }
}
