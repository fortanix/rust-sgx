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
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Connected {
        proxy_port: u32,
    },
}
