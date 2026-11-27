use fortanix_vme_abi::{Addr};

use crate::Error;

#[derive(Clone, Debug)]
pub enum ConnectionInfo {
    Listener {
        /// The local address (of the runner) the socket is bound to
        local: Addr,
        /// The vsock port the enclave is listening on to receive connections from the runner
        enclave_port: u32,
        /// the raw file descriptor of the socket, when available.
        fd: Option<i32>,
    },
    Stream {
        /// The vsock port the enclave is using to communicate with the runner
        enclave_port: u32,
        /// The local address the socket is bound to.
        local: Addr,
        /// The peer the socket is connected to.
        peer: Addr,
        /// the raw file descriptor of the socket, when available.
        fd: Option<i32>,
    },
}

impl ConnectionInfo {
    pub fn new_stream_info(
        enclave_port: u32,
        local: Addr,
        peer: Addr,
        fd: Option<i32>,
    ) -> Self {
        ConnectionInfo::Stream { enclave_port, local, peer, fd }
    }

    pub fn new_listener_info(
        local: Addr,
        enclave_port: u32,
        fd: Option<i32>,
    ) -> Self {
        ConnectionInfo::Listener { local, enclave_port, fd }
    }

    pub fn enclave_port(&self) -> u32 {
        match self {
            ConnectionInfo::Listener { enclave_port, .. } => *enclave_port,
            ConnectionInfo::Stream { enclave_port, .. } => *enclave_port,
        }
    }

    pub fn fd(&self) -> Result<i32, Error> {
        match self {
            ConnectionInfo::Listener {fd, .. } => fd.ok_or(Error::MissingFd),
            ConnectionInfo::Stream {fd, .. } => fd.ok_or(Error::MissingFd)
        }
    }
}