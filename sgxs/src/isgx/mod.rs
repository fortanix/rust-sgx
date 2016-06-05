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

mod ioctl;

use std::fs::OpenOptions;
use std::path::Path;
use std::os::unix::io::IntoRawFd;
use std::io::{Result as IoResult,Error as IoError};
use std::ptr;
use libc;
use sgxs::{SgxsRead,PageReader,MeasECreate,MeasEAdd,PageChunks,Error as SgxsError};
use abi::{Sigstruct,Einittoken,Secs,Secinfo,PageType,ErrorCode};

use loader::{Map,Load,Address,EinittokenError};

#[derive(Debug)]
pub enum SgxIoctlError {
	Io(IoError),
	Ret(ErrorCode),
}

#[derive(Debug)]
pub enum Error {
	Sgxs(SgxsError),
	Map(IoError),
	Create(SgxIoctlError),
	Add(SgxIoctlError),
	Init(SgxIoctlError),
}

impl From<SgxsError> for Error {
    fn from(err: SgxsError) -> Error {
        Error::Sgxs(err)
    }
}

impl EinittokenError for Error {
	#[allow(non_upper_case_globals)]
	fn is_einittoken_error(&self) -> bool {
		use self::Error::Init;
		use self::SgxIoctlError::Ret;
		match self {
			&Init(Ret(ErrorCode::InvalidEinitToken)) |
			&Init(Ret(ErrorCode::InvalidCpusvn)) |
			&Init(Ret(ErrorCode::InvalidAttribute)) | // InvalidEinitAttribute according to PR, but does not exist.
			&Init(Ret(ErrorCode::InvalidMeasurement)) => true,
			_ => false,
		}
	}
}

pub type Result<T> = ::std::result::Result<T, Error>;

macro_rules! try_ioctl_unsafe {
	( $f:ident, $v:expr ) => {{
		let ret=unsafe{$v};
		if ret == -1 {
			return Err(Error::$f(SgxIoctlError::Io(IoError::last_os_error())));
		} else if ret != 0 {
			return Err(Error::$f(SgxIoctlError::Ret(unsafe{::std::mem::transmute(ret)})));
		}
	}}
}

pub struct Mapping<'a> {
	device: &'a Device,
	tcss: Vec<Address>,
	base: u64,
	size: u64,
}

impl<'a> Map for Mapping<'a> {
	fn base_address(&self) -> Address {
		::private::loader::make_address(self.base)
	}

	fn tcss(&self) -> &[Address] {
		&self.tcss
	}
}

impl<'a> Mapping<'a> {
	fn new(dev: &'a Device, size: u64) -> Result<Mapping<'a>> {
		let ptr=unsafe{libc::mmap(ptr::null_mut(),size as usize,libc::PROT_NONE,libc::MAP_SHARED,dev.fd,0)};
		if ptr==ptr::null_mut() || ptr==libc::MAP_FAILED {
			Err(Error::Map(IoError::last_os_error()))
		} else {
			Ok(Mapping{device:dev,base:ptr as u64,size:size,tcss:vec![]})
		}
	}

	fn create(&mut self, ecreate: MeasECreate, sigstruct: &Sigstruct, einittoken: &Einittoken) -> Result<()> {
		assert_eq!(self.size,ecreate.size);
		let secs=Secs{
			baseaddr: self.base,
			size: ecreate.size,
			ssaframesize: ecreate.ssaframesize,
			miscselect: sigstruct.miscselect,
			attributes: if einittoken.valid==1 { einittoken.attributes.clone() } else { sigstruct.attributes.clone() },
			..Default::default()
		};
		let createdata=ioctl::CreateData{
			secs:&secs,
		};
		try_ioctl_unsafe!(Create,ioctl::create(self.device.fd,&createdata));
		Ok(())
	}

	fn add(&mut self, page: (MeasEAdd,PageChunks,[u8;4096])) -> Result<()> {
		let (eadd,chunks,data)=page;
		let secinfo=Secinfo{
			flags:eadd.secinfo.flags,
			..Default::default()
		};
		let adddata=ioctl::AddData{
			dstpage:self.base+eadd.offset,
			srcpage:&data,
			secinfo:&secinfo,
			chunks:chunks.0,
		};
		try_ioctl_unsafe!(Add,ioctl::add(self.device.fd,&adddata));
		if secinfo.flags.page_type()==PageType::Tcs as u8 {
			self.tcss.push(::private::loader::make_address(adddata.dstpage));
		}
		Ok(())
	}

	fn init(&self, sigstruct: &Sigstruct, einittoken: &Einittoken) -> Result<()> {
		let initdata=ioctl::InitData{
			base:self.base,
			sigstruct:sigstruct,
			einittoken:einittoken,
		};
		try_ioctl_unsafe!(Init,ioctl::init(self.device.fd,&initdata));
		Ok(())
	}
}

impl<'a> Drop for Mapping<'a> {
	fn drop(&mut self) {
		unsafe{libc::munmap(self.base as usize as *mut _,self.size as usize)};
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
}

impl<'dev> Load<'dev> for Device {
	type Mapping=Mapping<'dev>;
	type Error=Error;

	fn load<'r, R: SgxsRead + 'r>(&'dev self, reader: &'r mut R, sigstruct: &Sigstruct, einittoken: Option<&Einittoken>) -> Result<Mapping<'dev>> {
		let einittoken_default;
		let einittoken=einittoken.unwrap_or({einittoken_default=Default::default();&einittoken_default});

		let (ecreate,mut reader)=try!(PageReader::new(reader));

		let mut mapping=try!(Mapping::new(self,ecreate.size));

		try!(mapping.create(ecreate,sigstruct,einittoken));

		loop {
			match try!(reader.read_page()) {
				Some(page) => try!(mapping.add(page)),
				None => break
			}
		}

		try!(mapping.init(sigstruct,einittoken));

		Ok(mapping)
	}
}

impl Drop for Device {
	fn drop(&mut self) {
		unsafe{libc::close(self.fd)};
	}
}
