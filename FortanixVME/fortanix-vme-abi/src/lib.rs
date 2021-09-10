#![no_std]

extern crate alloc;

#[cfg(feature="std")]
extern crate std;

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

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Connected {
        port: u16,
        local_addr: String,
        peer_addr: String,
    },
}

#[derive(Debug)]
pub enum Error {
    SerializationError(serde_cbor::Error),
    DeserializationError(serde_cbor::Error),
    #[cfg(feature="std")]
    ConnectionError(IoError),
    AlreadyConnected,
}

#[cfg(feature="std")]
impl From<IoError> for Error {
    fn from(e: IoError) -> Error {
        Error::ConnectionError(e)
    }
}

pub struct Client {
    #[cfg(feature="std")]
    stream: Option<TcpStream>,
}

#[cfg(feature="std")]
impl Client {
    pub fn new() -> Self {
        Client {
            stream: None,
        }
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        if let Some(_) = self.stream {
            return Err(Error::AlreadyConnected);
        }

        let stream = TcpStream::connect(alloc::format!("localhost:{}", SERVER_PORT))?;
        self.stream = Some(stream);
        Ok(())
    }

    pub fn send(&mut self, req: Request) -> Result<Response, Error> {
        if let Some(stream) = self.stream.as_mut() {
            let req = serde_cbor::ser::to_vec(&req).map_err(|e| Error::SerializationError(e))?;
            stream.write(&req)?;

            let response = Self::read_from_stream(stream).unwrap();
            serde_cbor::from_slice(&response).map_err(|e| Error::DeserializationError(e))
        } else {
            Err(Error::AlreadyConnected)
        }
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
