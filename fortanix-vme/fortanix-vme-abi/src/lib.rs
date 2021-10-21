#![no_std]
extern crate alloc;
#[cfg(feature="std")]
extern crate std;

use alloc::string::String;
use serde::{Deserialize, Serialize};
#[cfg(feature="std")]
use std::net::SocketAddr;

pub const SERVER_PORT: u32 = 10000;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Connect {
        addr: String,
    },
    Bind {
        /// The address the listen on in the parent VM
        addr: String,
        /// The port the enclave is listening on to receive connections from the parent VM
        enclave_port: u32,
    },
    Accept {
        fd: i32,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg(feature="std")]
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

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Connected {
        proxy_port: u32,
    },
    Bound {
        /// The TCP port the runner is listening on
        port: u16,
        /// The id used to identify the listener. It can be used for subsequent calls (e.g., to
        /// accept new incoming connections)
        fd: i32,
    },
    IncomingConnection {
        /// The address of the remote party
        peer: Addr,
        /// The vsock port number the runner will connect to the enclave in order to forward the
        /// incomming connection
        proxy_port: u32,
    }
}

/*
#[cfg(test)]
mod test {
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use crate::Addr;

    #[test]
    fn test_addr() {
        let sock_addr = SocketAddr::from_str("10.11.12.13:4567").unwrap();
        if let Addr::IPv4 { port, ip } = sock_addr.into() {
            assert_eq!(IpAddr::from(ip), sock_addr.ip());   
            assert_eq!(port, sock_addr.port());
        } else {
            panic!("Not IPv4")
        }
    }
}
*/
