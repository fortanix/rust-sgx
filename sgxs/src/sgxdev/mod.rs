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

mod loader;
mod ioctl;

use std::fs::OpenOptions;
use std::path::Path;
use std::os::unix::io::IntoRawFd;
use std::io::{Result as IoResult,Error as IoError};
use std::borrow::BorrowMut;
use libc;
use sgxs::{SgxsRead,PageReader};
use abi::{Sigstruct,Einittoken};

use loader::{Map,Load};
use self::loader::{Pages,Uaddr,Kaddr};
pub use self::loader::{Result,Error};

pub struct Mapping<'a> {
	_pages: Pages<'a>,
	tcss: Vec<Uaddr>,
	base: Uaddr,
	size: u64,
}

impl<'a> Drop for Mapping<'a> {
	fn drop(&mut self) {
		unsafe{libc::munmap(self.base.0 as usize as *mut _,self.size as usize)};
	}
}

impl<'a> Mapping<'a> {
	#[allow(dead_code)]
	fn assert_u64_uaddr_same_size(a: Uaddr) -> u64 {
		unsafe{::std::mem::transmute(a)}
	}
}

impl<'a> Map for Mapping<'a> {
	fn base_address(&self) -> u64 {
		self.base.0
	}

	fn tcss(&self) -> &[u64] {
		unsafe{::std::mem::transmute(&self.tcss[..])}
	}
}

pub struct Device {
	fd: libc::c_int,
}

impl Device {
	pub fn open<P: AsRef<Path>>(path: P) -> IoResult<Device> {
		let file=try!(OpenOptions::new().read(true).write(true).open(path));
		Ok(Device{fd:file.into_raw_fd()})
	}

	fn base_address(&self) -> IoResult<Kaddr> {
		let mut out=ioctl::EnclsDataOut::default();
		let ret=unsafe{ioctl::ioaddr(self.fd,out.borrow_mut() as *mut _)};
		if ret<0 {
			Err(IoError::from_raw_os_error(-ret))
		} else {
			Ok(Kaddr(out.data))
		}
	}

	fn map(&self, offset: u64, size: usize) -> IoResult<Uaddr> {
		let ptr=unsafe{libc::mmap(0x17fffffffusize as *mut _,size,libc::PROT_NONE,libc::MAP_SHARED,self.fd,offset as i64)};
		if ptr==::std::ptr::null_mut() {
			Err(IoError::last_os_error())
		} else {
			Ok(Uaddr(ptr as u64))
		}
	}
}

impl<'dev> Load<'dev> for Device {
	type Mapping=Mapping<'dev>;
	type Error=Error;

	fn load<'r, R: SgxsRead + 'r>(&'dev self, reader: &'r mut R, sigstruct: &Sigstruct, einittoken: Option<&Einittoken>) -> Result<Mapping<'dev>> {
		let (ecreate,reader)=try!(PageReader::new(reader));
		let size=ecreate.size;

		let secs=try!(self.base_address());
		let epc_offset=0x1000;
		let k_base=secs+epc_offset;
		let base=try!(self.map(epc_offset,size as usize));

		let (tcss,pages)=try!(loader::load(&self,reader,ecreate,base,k_base,secs,sigstruct,einittoken));

		Ok(Mapping{_pages:pages,tcss:tcss,base:base,size:size})
	}
}

impl Drop for Device {
	fn drop(&mut self) {
		unsafe{libc::close(self.fd)};
	}
}
