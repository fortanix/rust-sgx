#![deny(warnings)]
#![no_std]
extern crate alloc;
#[cfg(feature="std")]
extern crate std;

pub const SERVER_PORT: u32 = 10000;

mod abi;
pub use abi::*;
