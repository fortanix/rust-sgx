#![no_std]

#[cfg(feature="std")]
extern crate std;
#[cfg_attr(feature = "rustc-dep-of-std", allow(unused_extern_crates))]
extern crate alloc;

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
    SystemError {
        errno: i32
    },
    IoError {
        error: IoError
    },
    SerializationError,
    DeserializationError,
    Other(String)
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
            vsock::Error::SystemError(errno) => Error::SystemError { errno },
            vsock::Error::WrongAddressType => {
                Error::InvalidInput
            }
            vsock::Error::ZeroDurationTimeout => {
                Error::InvalidInput
            }
            vsock::Error::WriteZero => {
                Error::IoError { error: IoError::WriteZero }
            }
            vsock::Error::UnexpectedEof => {
                Error::IoError { error: IoError::UnexpectedEof }
            }
        }
    }
}

#[cfg(test)]
mod test;