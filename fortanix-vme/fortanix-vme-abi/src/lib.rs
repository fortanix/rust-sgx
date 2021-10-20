#![no_std]
extern crate alloc;

use alloc::string::String;
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Connected {
        proxy_port: u32,
    },
    Bound {
        /// The TCP port the runner is listening on
        port: u16,
    },
}
