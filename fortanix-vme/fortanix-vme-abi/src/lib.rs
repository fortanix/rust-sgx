#![no_std]
extern crate alloc;

use core::convert::{TryFrom, TryInto};
use alloc::vec::Vec;
use alloc::string::String;
use serde::{Deserialize, Serialize};
use vsock::{self, Platform, VsockStream};

pub const SERVER_PORT: u32 = 1024;
const BUFF_SIZE: usize = 0x2000;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Connect {
        addr: String,
    },
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
        proxy_port: u32,
    },
}

impl TryInto<Vec<u8>> for Response {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Error> {
        serde_cbor::ser::to_vec(&self).map_err(|e| Error::SerializationError(e))
    }
}

impl TryFrom<&[u8]> for Response {
    type Error = Error;

    fn try_from(response: &[u8]) -> Result<Response, Error> {
        serde_cbor::from_slice(&response).map_err(|e| Error::DeserializationError(e))
    }
}

#[derive(Debug)]
pub enum Error {
    SerializationError(serde_cbor::Error),
    DeserializationError(serde_cbor::Error),
    ConnectFailed,
    WriteFailed,
    ReadFailed,
    UnexpectedResponse,
}

pub struct Client<P: Platform> {
    stream: VsockStream<P>,
}

impl<P: Platform> Client<P> {
    fn connect(port: u32) -> Result<VsockStream<P>, Error> {
        VsockStream::connect_with_cid_port(vsock::VMADDR_CID_HOST, port)
            .or_else(|_e| VsockStream::connect_with_cid_port(vsock::VMADDR_CID_LOCAL, port))
            .map_err(|_| Error::ConnectFailed)
    }

    pub fn new(port: u32) -> Result<Self, Error> {
        let stream = Self::connect(port)?;
        Ok(Client {
            stream,
        })
    }

    pub fn open_proxy_connection(&mut self, addr: String) -> Result<VsockStream<P>, Error> {
        let connect = Request::Connect {
            addr
        };
        self.send(connect)?;
        let Response::Connected{ proxy_port, .. } = self.receive()?;
        Self::connect(proxy_port)
    }

    fn send(&mut self, req: Request) -> Result<(), Error> {
        let req: Vec<u8> = req.try_into()?;
        self.stream.write(req.as_slice()).map(|_n| ()).map_err(|_e| Error::WriteFailed)
    }

    fn receive(&mut self) -> Result<Response, Error> {
        // We'd like to have used a streaming deserializer. Unfortunately, that implies that we
        // are abe to create a `Deserializer` from a reader (i.e., the socket). Unfortunately
        // that requires the socket to implement `std::io::Read` and this is not possible in a
        // `no_std` environment.
        fn read<P: Platform>(stream: &mut VsockStream<P>, prev_buff: Vec<u8>) -> Result<Response, Error> {
            let old_size = prev_buff.len();
            let mut buff = prev_buff;
            buff.resize(old_size + BUFF_SIZE, 0);
            let n = stream.read(&mut buff[old_size..]).map_err(|_e| Error::ReadFailed)?;
            buff.resize(old_size + n, 0);

            match Response::try_from(buff.as_slice()) {
                Ok(resp)                            => Ok(resp),
                Err(Error::DeserializationError(e)) => if e.is_eof() {
                        read(stream, buff)
                    } else {
                        Err(Error::DeserializationError(e))
                    },
                Err(e)                              => Err(e),
            }
        }
        read(&mut self.stream, Vec::new())
    }
}
