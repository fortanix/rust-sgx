/*
 * Rust API for the Intel Linux SGX driver.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

use abi;

#[repr(C)]
#[derive(Clone,Debug)]
pub struct CreateData {
	pub secs: *const abi::Secs, // with baseaddr set to 0
	pub base: u64,
}

#[repr(C)]
#[derive(Clone,Debug)]
pub struct AddData {
	pub dstpage: u64,
	pub srcpage: *const [u8;4096],
	pub secinfo: *const abi::Secinfo,
	pub not_measured: u32,
}

#[repr(C)]
#[derive(Clone,Debug)]
pub struct InitData {
	pub base: u64,
	pub sigstruct: *const abi::Sigstruct,
	pub einittoken: *const abi::Einittoken,
}

#[repr(C)]
#[derive(Clone,Debug)]
pub struct DestroyData {
	pub base: u64,
}

const SGX_IOCTL: u8 = 112;
ioctl!(readwrite create with SGX_IOCTL, 0x02; CreateData);
ioctl!(write add with SGX_IOCTL, 0x03; AddData);
ioctl!(write init with SGX_IOCTL, 0x04; InitData);
ioctl!(write destroy with SGX_IOCTL, 0x06; DestroyData);
