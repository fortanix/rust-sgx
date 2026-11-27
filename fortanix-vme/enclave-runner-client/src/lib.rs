#![no_std]

#[cfg(feature="std")]
extern crate std;
#[cfg_attr(feature = "rustc-dep-of-std", allow(unused_extern_crates))]
extern crate alloc;

use core::fmt::{Display, Error as FmtError, Formatter};
use alloc::string::{String, ToString};

// libc is only used without `std` (errno in the no_std path). This prevents
// "unused dependency" warnings from showing up in std builds
#[cfg(feature = "std")]
use libc as _;

mod fortanixvme;

mod connection_info;
pub use connection_info::*;

mod client;
pub use client::*;

pub use fortanix_vme_abi::{Addr, ErrorKind as IoError};
pub use vsock::SockAddr as VsockAddr; 

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    SystemError(i32),
    IoError(IoError),
    SerializationError,
    DeserializationError,
    MissingFd,
    Other(String)
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        match self {
            Error::InvalidInput => write!(f, "invalid input"),
            Error::SystemError(errno) => write!(f, "system error {}", errno),
            Error::IoError(error) => write!(f, "I/O error: {:?}", error),
            Error::SerializationError => write!(f, "serialization error"),
            Error::DeserializationError => write!(f, "deserialization error"),
            Error::MissingFd => write!(f, "missing file descriptor"),
            Error::Other(reason) => write!(f, "{}", reason),
        }
    }
}

impl From<vsock::Error> for Error {
    fn from(err: vsock::Error) -> Error {
        match err {
            vsock::Error::EntropyError => {
                Error::Other("EntropyError".to_string())
            }
            vsock::Error::ReservedPort => {
                Error::InvalidInput
            }
            vsock::Error::SystemError(errno) => Error::SystemError(errno),
            vsock::Error::WrongAddressType => {
                Error::InvalidInput
            }
            vsock::Error::ZeroDurationTimeout => {
                Error::InvalidInput
            }
            vsock::Error::WriteZero => {
                Error::IoError(IoError::WriteZero)
            }
            vsock::Error::UnexpectedEof => {
                Error::IoError(IoError::UnexpectedEof)
            }
        }
    }
}

#[cfg(test)]
mod test;