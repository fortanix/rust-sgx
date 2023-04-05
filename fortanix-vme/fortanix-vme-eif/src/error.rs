use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Creating initramfs failed")]
    InitramfsWriteError(#[source] io::Error),
    #[error("Reading initramfs failed")]
    InitramfsParseError(#[source] io::Error),
    #[error("Can't extract data from initramfs")]
    InitramfsExtractError(#[source] io::Error),
    #[error("Expected trailer in initramfs missing")]
    InitramfsExpectedTrailer,
    #[error("Unexpected data in initramfs file {path:?} (found \"{found:?}\", expected \"{expected:?}\")")]
    InitramfsUnexpectedData {
        path: String,
        found: String,
        expected: String,
    },
    #[error("Writing kernel to file failed")]
    KernelWriteError(#[source] io::Error),
    #[error("Writing kernel config to file failed")]
    KernelConfigWriteError(#[source] io::Error),
    #[error("Generating Eif info failed: {error}")]
    EifIdentityInfoError{
        error: String,
    },
    #[error("Writing Eif failed")]
    EifWriteError(#[source] io::Error),
    #[error("Invalid entry name (found \"{found:?}\", expected \"{expected:?}\")")]
    WrongEntryName {
        found: String,
        expected: String,
    },
    #[error("Unexpected uid (found \"{found:?}\", expected \"{expected:?}\")")]
    WrongUid {
        found: u32,
        expected: u32,
    },
    #[error("Unexpected gid (found \"{found:?}\", expected \"{expected:?}\")")]
    WrongGid {
        found: u32,
        expected: u32,
    },
    #[error("Unexpected mode (found \"{found:?}\", expected \"{expected:?}\")")]
    WrongMode {
        found: u32,
        expected: u32,
    },
}

impl Error {
    pub fn unexpected_data(path: String, found: String, expected: String) -> Self {
        Error::InitramfsUnexpectedData {
            path,
            found,
            expected,
        }
    }

    pub fn eif_identity_info(error: String) -> Self {
        Error::EifIdentityInfoError {
            error,
        }
    }

    pub fn wrong_entry_name(found: String, expected: String) -> Self {
        Error::WrongEntryName {
            found,
            expected,
        }
    }

    pub fn wrong_uid(found: u32, expected: u32) -> Self {
        Error::WrongUid {
            found,
            expected,
        }
    }

    pub fn wrong_gid(found: u32, expected: u32) -> Self {
        Error::WrongGid {
            found,
            expected,
        }
    }

    pub fn wrong_mode(found: u32, expected: u32) -> Self {
        Error::WrongMode {
            found,
            expected,
        }
    }
}
