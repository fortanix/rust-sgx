#![deny(warnings)]
#![no_std]

#[cfg(feature="std")]
extern crate std;

#[cfg(all(feature="alloc", not(feature="std")))]
use {
    alloc::string::String,
    alloc::vec::Vec,
};
#[cfg(all(feature="std", not(feature="alloc")))]
use {
    std::string::String,
    std::vec::Vec,
};

#[cfg(feature="core")]
use core::net::{IpAddr, SocketAddr};
#[cfg(all(feature="std", not(feature="core")))]
use std::net::{IpAddr, SocketAddr};

#[cfg(feature="std")]
use std::io;

pub const SERVER_PORT: u32 = 10000;

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Connect {
        addr: String,
    },
    Bind {
        /// The address the listen to in the parent VM
        addr: String,
        /// The port the enclave is listening on to receive connections from the parent VM. This
        /// port will also be used to reference the connection
        enclave_port: u32,
    },
    Accept {
        /// The Vsock port the enclave is listening on
        enclave_port: u32,
    },
    Close {
        enclave_port: u32,
    },
    Info {
        enclave_port: u32,
        runner_port: Option<u32>,
    },
    Exit {
        code: i32,
    },
    Init,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addr {
    IPv4 {
        ip: [u8; 4],
        port: u16,
    },
    IPv6 {
        ip: [u8; 16],
        port: u16,
        flowinfo: u32,
        scope_id: u32,
    },
}

#[cfg(any(feature="core", feature="std"))]
impl From<SocketAddr> for Addr {
    fn from(addr: SocketAddr) -> Addr {
        match addr {
            SocketAddr::V4(addr) => {
                Addr::IPv4 {
                    ip: addr.ip().octets(),
                    port: addr.port(),
                }
            },
            SocketAddr::V6(addr) => {
                Addr::IPv6 {
                    ip: addr.ip().octets(),
                    port: addr.port(),
                    flowinfo: addr.flowinfo(),
                    scope_id: addr.scope_id(),
                }
            }
        }
    }
}

#[cfg(any(feature="core", feature="std"))]
impl From<Addr> for SocketAddr {
    fn from(addr: Addr) -> SocketAddr {
        match addr {
            Addr::IPv4{ ip, port } => {
                SocketAddr::new(IpAddr::V4(ip.into()), port)
            },
            Addr::IPv6{ ip, port, .. } => {
                SocketAddr::new(IpAddr::V6(ip.into()), port)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Connected {
        /// The vsock port the proxy is listening on for an incoming connection
        proxy_port: u32,
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party
        peer: Addr,
    },
    Bound {
        /// The local TCP address the parent VM is listening on
        local: Addr,
    },
    IncomingConnection {
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party
        peer: Addr,
        /// The vsock port number the runner will connect to the enclave in order to forward the
        /// incoming connection
        proxy_port: u32,
    },
    Closed,
    Info {
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party for open connection, None for server sockets
        peer: Option<Addr>,
    },
    // TODO Split up failed command (e.g., bind executed on behalve of runner errored) and
    // errored runner (e.g., no info was found for fd).
    Failed(Error),
    Init {
        args: Vec<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    NetworkDown,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    ReadOnlyFilesystem,
    FilesystemLoop,
    StaleNetworkFileHandle,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    StorageFull,
    NotSeekable,
    FilesystemQuotaExceeded,
    FileTooLarge,
    ResourceBusy,
    ExecutableFileBusy,
    Deadlock,
    CrossesDevices,
    TooManyLinks,
    //FilenameTooLong,
    ArgumentListTooLong,
    Interrupted,
    Unsupported,
    UnexpectedEof,
    OutOfMemory,
    Other,
    Uncategorized,
}

#[cfg(feature="std")]
impl From<io::ErrorKind> for ErrorKind {
    fn from(kind: io::ErrorKind) -> ErrorKind {
        match kind {
            io::ErrorKind::NotFound => ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused => ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset => ErrorKind::ConnectionReset,
            // Unstable std library feature io_error_more
            //io::ErrorKind::HostUnreachable => ErrorKind::HostUnreachable,
            // Unstable std library feature io_error_more
            //io::ErrorKind::NetworkUnreachable => ErrorKind::NetworkUnreachable,
            io::ErrorKind::ConnectionAborted => ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected => ErrorKind::NotConnected,
            io::ErrorKind::AddrInUse => ErrorKind::AddrInUse,
            io::ErrorKind::AddrNotAvailable => ErrorKind::AddrNotAvailable,
            // Unstable std library feature io_error_more
            //io::ErrorKind::NetworkDown => ErrorKind::NetworkDown,
            io::ErrorKind::BrokenPipe => ErrorKind::BrokenPipe,
            io::ErrorKind::AlreadyExists => ErrorKind::AlreadyExists,
            io::ErrorKind::WouldBlock => ErrorKind::WouldBlock,
            // Unstable std library feature io_error_more
            //io::ErrorKind::NotADirectory => ErrorKind::NotADirectory,
            // Unstable std library feature io_error_more
            //io::ErrorKind::IsADirectory => ErrorKind::IsADirectory,
            // Unstable std library feature io_error_more
            //io::ErrorKind::DirectoryNotEmpty => ErrorKind::DirectoryNotEmpty,
            // Unstable std library feature io_error_more
            //io::ErrorKind::ReadOnlyFilesystem => ErrorKind::ReadOnlyFilesystem,
            // Unstable std library feature io_error_more
            //io::ErrorKind::FilesystemLoop => ErrorKind::FilesystemLoop,
            // Unstable std library feature io_error_more
            //io::ErrorKind::StaleNetworkFileHandle => ErrorKind::StaleNetworkFileHandle,
            io::ErrorKind::InvalidInput => ErrorKind::InvalidInput,
            io::ErrorKind::InvalidData => ErrorKind::InvalidData,
            io::ErrorKind::TimedOut => ErrorKind::TimedOut,
            io::ErrorKind::WriteZero => ErrorKind::WriteZero,
            // Unstable std library feature io_error_more
            //io::ErrorKind::StorageFull => ErrorKind::StorageFull,
            // Unstable std library feature io_error_more
            //io::ErrorKind::NotSeekable => ErrorKind::NotSeekable,
            // Unstable std library feature io_error_more
            //io::ErrorKind::FilesystemQuotaExceeded => ErrorKind::FilesystemQuotaExceeded,
            // Unstable std library feature io_error_more
            //io::ErrorKind::FileTooLarge => ErrorKind::FileTooLarge,
            // Unstable std library feature io_error_more
            //io::ErrorKind::ResourceBusy => ErrorKind::ResourceBusy,
            // Unstable std library feature io_error_more
            //io::ErrorKind::ExecutableFileBusy => ErrorKind::ExecutableFileBusy,
            // Unstable std library feature io_error_more
            //io::ErrorKind::Deadlock => ErrorKind::Deadlock,
            // Unstable std library feature io_error_more
            //io::ErrorKind::CrossesDevices => ErrorKind::CrossesDevices,
            // Unstable std library feature io_error_more
            //io::ErrorKind::TooManyLinks => ErrorKind::TooManyLinks,
            // Unstable std library feature
            //io::ErrorKind::FilenameTooLong => ErrorKind::FilenameTooLong,
            // Unstable std library feature io_error_more
            //io::ErrorKind::ArgumentListTooLong => ErrorKind::ArgumentListTooLong,
            io::ErrorKind::Interrupted => ErrorKind::Interrupted,
            io::ErrorKind::Unsupported => ErrorKind::Unsupported,
            io::ErrorKind::UnexpectedEof => ErrorKind::UnexpectedEof,
            io::ErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
            io::ErrorKind::Other => ErrorKind::Other,
            // Unstable std library feature io_error_uncategorized
            //io::ErrorKind::Uncategorized => ErrorKind::Uncategorized,
            _ => ErrorKind::Other,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    ConnectionNotFound,
    SystemError(i32),
    Unknown,
    VsockError,
    /// Command executed on behalf of enclave (e.g., bind, accept, ...) resulted in an error. 
    ///   This error itself should be returned as the result of the command.
    Command(ErrorKind),
}

#[cfg(feature="std")]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        if let Some(errno) = error.raw_os_error() {
            Error::SystemError(errno)
        } else {
            Error::Unknown
        }
    }
}

#[cfg(test)]
mod test;

#[cfg(feature="serde")]
mod serde_impls;
