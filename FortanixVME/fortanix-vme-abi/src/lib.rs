#![no_std]

extern crate alloc;

#[cfg(feature="std")]
extern crate std;

use serde_cbor::Error;
use alloc::vec::Vec;
use alloc::string::String;
use serde::{Deserialize, Serialize};
#[cfg(feature="std")]
use std::io::{Error as IoError, Read, Write};
#[cfg(feature="std")]
use std::net::TcpStream;

#[cfg(feature="std")]
pub const SERVER_PORT: u16 = 1024;
const BUFF_SIZE: usize = 1024;

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

pub struct Client {
    #[cfg(feature="std")]
    stream: TcpStream,
}

#[cfg(feature="std")]
impl Client {
    pub fn new() -> Self {
        Client{
            stream: TcpStream::connect(alloc::format!("localhost:{}", SERVER_PORT)).unwrap(),
        }
    }

    pub fn send(&mut self, req: Request) -> Response {
        let req = req.serialize().unwrap();
        self.stream.write(&req).unwrap();

        let response = Self::read_from_stream(&mut self.stream).unwrap();
        Response::deserialize(&response).unwrap()
    }

    fn read_from_stream(stream: &mut TcpStream) -> Result<Vec<u8>, IoError> {
        let mut buff = [0; BUFF_SIZE];
        let n = stream.read(&mut buff)?;
        let mut buff = buff[0..n].to_vec();
        //TODO This will block when the n*BUFF_SIZE bytes need to be read
        if n == BUFF_SIZE {
            buff.append(&mut Self::read_from_stream(stream)?);
        }
        Ok(buff)
    }
}
