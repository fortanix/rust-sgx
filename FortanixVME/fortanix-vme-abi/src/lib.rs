#![no_std]
#![allow(unused)]

extern crate alloc;

use serde_cbor::{Error, Serializer};
use serde_cbor::ser::SliceWrite;
use alloc::vec::Vec;
use alloc::string::String;
use serde::{Deserialize, Serialize};

pub const SERVER_PORT: u16 = 1024;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Connect {
        addr: String,
    },
}

impl Request{
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        serde_cbor::ser::to_vec(self)
    }

    pub fn deserialize(req: &Vec<u8>) -> Result<Self, Error> {
        serde_cbor::from_slice(req)
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
        serde_cbor::ser::to_vec(self)
    }

    pub fn deserialize(res: &Vec<u8>) -> Result<Self, Error> {
        serde_cbor::from_slice(res)
    }
}
