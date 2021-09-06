#![no_std]
#![allow(unused)]

extern crate alloc;

use alloc::string::String;

pub const SERVER_PORT: u16 = 1024;

pub enum Request {
    Connect {
        addr: String,
    },
}

enum Response {
    Connected {
        port: u16,
        local_addr: String,
        peer_addr: String,
    },
}

enum Error {
}
