/*
 * Rust API for the SGX Linux ioctl driver.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#![allow(dead_code)]

use abi;
use libc;

// === START UNION FUDGE ===
// All this can be changed once repr(union) is implemented
#[repr(C)]
#[derive(Clone,Default)]
pub struct EnclsData([u64; 4]);

#[repr(C)]
#[derive(Clone,Debug,Default)]
pub struct EnclsDataIn {
	pub rbx: u64,
	pub rcx: u64,
	pub rdx: u64,
	pub _pad: u64,
}

#[repr(C)]
#[derive(Clone,Debug,Default)]
pub struct EnclsDataOut {
	pub exception: i32,
	pub data: u64,
	pub duration_encls: u64,
	pub duration_copy: u64,
}

use std::mem::transmute;
use std::convert::From;
use std::borrow::Borrow;
use std::borrow::BorrowMut;

macro_rules! impl_from_and_borrow {
	( $t1:ty as $t2:ty  ) => {
		impl From<$t1> for $t2 {
			fn from(data: $t1) -> $t2 {
				unsafe{transmute(data)}
			}
		}

		impl Borrow<$t2> for $t1 {
			fn borrow(&self) -> &$t2 {
				unsafe{transmute(self)}
			}
		}

		impl BorrowMut<$t2> for $t1 {
			fn borrow_mut(&mut self) -> &mut $t2 {
				unsafe{transmute(self)}
			}
		}
	};
}

impl_from_and_borrow!(EnclsDataIn as EnclsData);
impl_from_and_borrow!(EnclsData as EnclsDataIn);
impl_from_and_borrow!(EnclsDataOut as EnclsData);
impl_from_and_borrow!(EnclsData as EnclsDataOut);

// === END UNION FUDGE ===

#[repr(C)]
pub struct IoctlVecElem {
	pub leaf: i32,
	pub return_flag: ReturnFlags,
	pub data: EnclsData,
}

#[repr(C)]
pub struct IoctlVec {
	pub num: i32,
	pub ioctls: *mut IoctlVecElem,
}

bitflags! {
	flags ReturnFlags: i32 {
		const EXCEPTION    = 0b0000_0001, // return if an exception was encountered executing ENCLS
		const ERROR        = 0b0000_0010, // return if EAX was not 0 after ENCLS
		const ERROR_EBLOCK = 0b0000_0100, // same as RETURN_ERROR but also continue on SGX_BLKSTATE
	}
}

const SGX_IOCTL: u8 = b'G';
pub unsafe fn encls(fd: libc::c_int, leaf: abi::Encls, data: *mut EnclsData) {
	libc::ioctl(fd, iorw!(SGX_IOCTL, leaf, ::std::mem::size_of::<EnclsData>()) as libc::c_ulong, data);
}

const SGX_META_IOCTL: u8 = b'H';
ioctl!(read ioaddr with SGX_META_IOCTL, 0x00; EnclsData);
ioctl!(readwrite multi_encls with SGX_META_IOCTL, 0x01; IoctlVec);
