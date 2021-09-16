#![no_std]

extern crate alloc;

#[cfg(feature="std")]
extern crate std;

use core::fmt::{self, Display};
use core::convert::{TryFrom, TryInto};
use alloc::vec::Vec;
use alloc::string::String;
use serde::{Deserialize, Serialize};
#[cfg(feature="std")]
use std::io::{Error as IoError, Read, Write};
#[cfg(feature="std")]
use std::net::TcpStream;

pub const SERVER_PORT: u16 = 1024;
const BUFF_SIZE: usize = 2048;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Connect {
        addr: String,
    },
}

impl TryFrom<&[u8]> for Request {
    type Error = Error;

    fn try_from(request: &[u8]) -> Result<Request, Error> {
        serde_cbor::from_slice(&request).map_err(|e| Error::DeserializationError(e))
    }
}

impl TryInto<Vec<u8>> for Request {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Error> {
        serde_cbor::ser::to_vec(&self).map_err(|e| Error::SerializationError(e))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Connected {
        port: u32,
        local_addr: String,
        peer_addr: String,
    },
}

impl TryFrom<&[u8]> for Response {
    type Error = Error;

    fn try_from(response: &[u8]) -> Result<Response, Error> {
        serde_cbor::from_slice(&response).map_err(|e| Error::DeserializationError(e))
    }
}

impl TryInto<Vec<u8>> for Response {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Error> {
        serde_cbor::ser::to_vec(&self).map_err(|e| Error::SerializationError(e))
    }
}

#[derive(Debug)]
pub enum Error {
    SerializationError(serde_cbor::Error),
    DeserializationError(serde_cbor::Error),
    ConnectionFailed,
    WriteFailed,
    ReadFailed,
    UnexpectedResponse,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "todo")
    }
}

#[cfg(feature="std")]
impl From<IoError> for Error {
    fn from(_e: IoError) -> Error {
        Error::ConnectionFailed
    }
}

pub struct Client<T: EnclaveRunnerConnection> {
    stream: T,
}

pub trait EnclaveRunnerConnection where Self: Sized {
    fn create_connection(port: Option<u32>) -> Result<Self, Error>;
    fn send_to_runner(&mut self, buff: &[u8]) -> Result<(), Error>;
    fn receive_from_runner(&mut self, buff: &mut [u8]) -> Result<usize, Error>;
}

#[cfg(feature="std")]
impl EnclaveRunnerConnection for TcpStream {
    fn create_connection(port: Option<u32>) -> Result<Self, Error> {
        TcpStream::connect(alloc::format!("localhost:{}", port.unwrap_or(SERVER_PORT as _))).map_err(|_| Error::ConnectionFailed)
    }

    fn send_to_runner(&mut self, buff: &[u8]) -> Result<(), Error> {
        self.write(buff).map_err(|_| Error::WriteFailed)?;
        Ok(())
    }

    fn receive_from_runner(&mut self, buff: &mut [u8]) -> Result<usize, Error> {
        self.read(buff).map_err(|_| Error::ReadFailed)
    }
}

impl<T: EnclaveRunnerConnection> Client<T> {
    pub fn new(port: Option<u32>) -> Result<Self, Error> {
        let stream = T::create_connection(port)?;

        Ok(Client {
            stream,
        })
    }

    pub fn open_proxy_connection(&mut self, addr: String) -> Result<u32, Error> {
        let connect = Request::Connect {
            addr
        };
        self.send(connect)?;
        if let Response::Connected{ port: proxy_port, .. } = self.receive()? {
            Ok(proxy_port)
        } else {
            Err(Error::UnexpectedResponse)
        }
    }

    pub fn send(&mut self, req: Request) -> Result<(), Error> {
        let req: Vec<u8> = req.try_into()?;
        self.stream.send_to_runner(&req)
    }

    fn read_all(&mut self) -> Result<Vec<u8>, Error> {
        let mut buff = [0; BUFF_SIZE];
        let n = self.stream.receive_from_runner(&mut buff)?;
        let mut buff = buff[0..n].to_vec();
        //TODO This will block when the n*BUFF_SIZE bytes need to be read
        if n == BUFF_SIZE {
            buff.append(&mut self.read_all()?);
        }
        Ok(buff)
    }

    pub fn receive(&mut self) -> Result<Response, Error> {
        let response = self.read_all()?;
        Response::try_from(response.as_slice())
    }
}

#[cfg(feature="std")]
impl<T: EnclaveRunnerConnection + Read> Read for Client<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        self.stream.read(buf)
    }
}

#[cfg(feature="std")]
impl<T: EnclaveRunnerConnection + Write> Write for Client<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.stream.flush()
    }
}
