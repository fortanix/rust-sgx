#![no_std]
#![allow(unused)]

extern crate alloc;

#[cfg(feature="std")]
extern crate std;

use core::fmt::{self, Display};
use serde_cbor::Serializer;
use serde_cbor::ser::SliceWrite;
use alloc::vec::Vec;
use alloc::string::String;
use serde::{Deserialize, Serialize};
#[cfg(feature="std")]
use std::io;

pub const SERVER_PORT: u16 = 1024;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Connect {
        addr: String,
    },
}

impl Request{
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        serde_cbor::ser::to_vec(self).map_err(|e| Error::SerializationError(e))
    }

    pub fn deserialize(req: &Vec<u8>) -> Result<Self, Error> {
        serde_cbor::from_slice(req).map_err(|e| Error::DeserializationError(e))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Connected {
        port: u16,
        local_addr: String,
        peer_addr: String,
    },
}

impl Response {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        serde_cbor::ser::to_vec(self).map_err(|e| Error::SerializationError(e))
    }

    pub fn deserialize(res: &Vec<u8>) -> Result<Self, Error> {
        serde_cbor::from_slice(res).map_err(|e| Error::DeserializationError(e))
    }
}

#[derive(Debug)]
pub enum Error {
    DeserializationError(serde_cbor::Error),
    ReadFailed,
    SerializationError(serde_cbor::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DeserializationError(_e) => write!(f, "Deserialization failed"),
            Error::ReadFailed               => write!(f, "Read failed"),
            Error::SerializationError(_e)   => write!(f, "Serialization failed"),
        }
    }
}
