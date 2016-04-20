/*
 * Rust API for the SGX Linux ioctl driver.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

mod loader;
mod ioctl;

use std::fs::OpenOptions;
use std::path::Path;
use std::os::unix::io::IntoRawFd;
use std::io::{Result as IoResult,Error as IoError};
use std::borrow::{Borrow,BorrowMut};
use libc;
use sgxs::{SgxsRead,PageReader};
use abi::{Sigstruct,Einittoken,Encls};

use loader::{Map,Load,Address};
use self::loader::{Pages,Uaddr,Kaddr};
pub use self::loader::{Result,Error};

pub struct Mapping<'a> {
	_pages: Option<Pages<'a>>,
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
	fn assert_address_uaddr_same_size(a: Uaddr) -> Address {
		unsafe{::std::mem::transmute(a)}
	}
}

impl<'a> Map for Mapping<'a> {
	fn base_address(&self) -> Address {
		::private::loader::make_address(self.base.0)
	}

	fn tcss(&self) -> &[Address] {
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

	pub fn debug_read(&self, addr: u64, len: usize) -> IoResult<(Vec<u64>,Vec<u64>)> {
		use self::ioctl::*;

		let addr=try!(self.base_address()).0+addr;

		let mut ioctls: Vec<IoctlVecElem>=(0..(len as u64)).map(|i|
			IoctlVecElem{
				leaf: Encls::EDbgrd as i32,
				return_flag: ReturnFlags::empty(),
				data: EnclsData::from(EnclsDataIn{
					rcx: addr+i*8,
					..Default::default()
				}),
			}
		).collect();

		let mut ioctl_param=IoctlVec{num:ioctls.len() as i32,ioctls:ioctls.as_mut_ptr() as *mut _};
		let ret=unsafe{multi_encls(self.fd,&mut ioctl_param)} as i32;
		if ret<0 {
			return Err(IoError::from_raw_os_error(-ret).into());
		}

		let mut errors=vec![];
		Ok((ioctls.into_iter().enumerate().map(|(i,ioctl_call)| {
			let dout: &EnclsDataOut=ioctl_call.data.borrow();
			if dout.exception!=-1 {
				errors.push(addr+(i as u64)*8);
				0
			} else {
				dout.data
			}
		}).collect(),errors))
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

	fn map(&self, offset: u64, size: usize) -> IoResult<Mapping> {
		let ptr=unsafe{libc::mmap(0x17fffffffusize as *mut _,size,libc::PROT_NONE,libc::MAP_SHARED,self.fd,offset as i64)};
		if ptr==::std::ptr::null_mut() {
			Err(IoError::last_os_error())
		} else {
			Ok(Mapping{_pages:None,tcss:Vec::with_capacity(0),base:Uaddr(ptr as u64),size:size as u64})
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
		let mut mapping=try!(self.map(epc_offset,size as usize));

		let (tcss,pages)=try!(loader::load(&self,reader,ecreate,mapping.base,k_base,secs,sigstruct,einittoken));

		mapping._pages=Some(pages);
		mapping.tcss=tcss;
		Ok(mapping)
	}
}

impl Drop for Device {
	fn drop(&mut self) {
		unsafe{libc::close(self.fd)};
	}
}
