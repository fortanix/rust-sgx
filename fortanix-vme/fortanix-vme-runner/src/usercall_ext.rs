use core::net::SocketAddr;
use std::{
    io::{self, Read, Result as IoResult, Write},
    net::{TcpListener, TcpStream},
    os::fd::RawFd,
};

pub trait UsercallExtension: 'static + Send + Sync + std::fmt::Debug {
    fn connect_stream(&self, addr: &str) -> IoResult<Option<Box<dyn SocketStream>>> {
        let _ = addr;
        Ok(None)
    }
    fn bind_stream(&self, addr: &str) -> IoResult<Option<(Box<dyn Listener>, SocketAddr)>> {
        let _ = addr;
        Ok(None)
    }
}

impl<T: UsercallExtension> From<T> for Box<dyn UsercallExtension> {
    fn from(value: T) -> Box<dyn UsercallExtension> {
        Box::new(value)
    }
}

#[derive(Debug)]
pub struct UsercallExtensionDefault;
impl UsercallExtension for UsercallExtensionDefault {}

pub trait SocketStream: Read + Write + 'static + Send + Sync {
    fn local_addr(&self) -> IoResult<SocketAddr>;
    fn peer_addr(&self) -> IoResult<SocketAddr>;
    fn as_raw_fd(&self) -> RawFd;
    fn shutdown(&self, how: std::net::Shutdown) -> IoResult<()>;
}

impl SocketStream for TcpStream {
    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.local_addr()
    }

    fn peer_addr(&self) -> IoResult<SocketAddr> {
        self.peer_addr()
    }

    fn as_raw_fd(&self) -> RawFd {
        std::os::fd::AsRawFd::as_raw_fd(self)
    }

    fn shutdown(&self, how: std::net::Shutdown) -> IoResult<()> {
        self.shutdown(how)
    }
}

impl<T: SocketStream + ?Sized> SocketStream for Box<T> {
    fn local_addr(&self) -> IoResult<SocketAddr> {
        (**self).local_addr()
    }

    fn peer_addr(&self) -> IoResult<SocketAddr> {
        (**self).peer_addr()
    }

    fn as_raw_fd(&self) -> RawFd {
        (**self).as_raw_fd()
    }

    fn shutdown(&self, how: std::net::Shutdown) -> IoResult<()> {
        (**self).shutdown(how)
    }
}

/// Listener lets an implementation implement a slightly modified form of `std::net::TcpListener::accept`.
pub trait Listener: 'static + Send {
    /// The enclave may optionally request the local or peer addresses
    /// be returned in `local_addr` or `peer_addr`, respectively.
    /// If `local_addr` and/or `peer_addr` are not `None`, they will point to an empty `String`.
    /// On success, user-space can fill in the strings as appropriate.
    ///
    /// The enclave must not make any security decisions based on the local address received.
    fn accept(&mut self) -> io::Result<(Box<dyn SocketStream>, SocketAddr)>;
    fn local_addr(&self) -> IoResult<SocketAddr>;
}

impl Listener for TcpListener {
    fn accept(&mut self) -> io::Result<(Box<dyn SocketStream>, SocketAddr)> {
        TcpListener::accept(&self)
            .map(|(stream, addr)| (Box::new(stream) as Box<dyn SocketStream>, addr))
    }
    
    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.local_addr()
    }
}
