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
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate ioctl as ioctl_crate;
extern crate libc;
extern crate byteorder;
extern crate openssl;
extern crate openssl_sys;
extern crate foreign_types;
#[cfg(feature="with-rust-crypto")]
extern crate crypto as rust_crypto;
extern crate core;
extern crate sgx_isa as abi;
extern crate time;

pub mod crypto;
pub mod isgx;
pub mod sgxs;
mod intelcall;
pub mod loader;
pub mod sigstruct;
pub mod util;

mod private {
	pub mod loader {
		#[derive(Clone,Copy,PartialEq,Eq,Debug)]
		pub struct Address(u64);

		impl From<Address> for u64 {
			fn from(a: Address) -> u64 {
				a.0
			}
		}

		// A `Tcs` represents the only reference to an in-memory TCS. Aliasing
		// (or lack thereof) is supposed to prevent entering the same TCS more
		// than once.
		#[derive(PartialEq,Eq,Debug)]
		pub struct Tcs(u64);

		impl Tcs {
			/// The caller must make sure that the Address is no longer in use when the
			/// `Tcs` leaves its scope
			pub unsafe fn address(&mut self) -> Address {
				make_address(self.0)
			}
		}

		pub fn make_address(a: u64) -> Address{
			Address(a)
		}

		pub fn make_tcs(a: u64) -> Tcs{
			Tcs(a)
		}
	}
}

#[cfg(target_endian="big")] const E:ENDIANNESS_NOT_SUPPORTED=();
