/*
 * The Rust SGXS library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#![feature(asm)]
#![feature(unsafe_no_drop_flag)]
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate ioctl as ioctl_crate;
extern crate libc;
extern crate byteorder;
extern crate openssl;
#[cfg(feature="with-rust-crypto")]
extern crate crypto as rust_crypto;
extern crate core;
extern crate sgx_isa as abi;
extern crate time;

pub mod crypto;
pub mod sgxdev;
pub mod isgx;
pub mod sgxs;
mod intelcall;
pub mod loader;
pub mod sigstruct;

mod private {
	pub mod loader {
		#[derive(Clone,Copy,PartialEq,Eq,Debug)]
		pub struct Address(u64);

		impl From<Address> for u64 {
			fn from(a: Address) -> u64 {
				a.0
			}
		}

		pub fn make_address(a: u64) -> Address{
			Address(a)
		}
	}
}

#[cfg(target_endian="big")] const E:ENDIANNESS_NOT_SUPPORTED=();
