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
use libc;
use sgxs::{SgxsRead,PageReader,MeasECreate,MeasEAdd,PageChunks,Error as SgxsError};
use abi::{Sigstruct,Einittoken,Secs,Secinfo,PageType,ErrorCode};

use loader::{Map,Load,Tcs,Address,EinittokenError};

#[derive(Debug)]
pub enum SgxIoctlError {
	Io(IoError),
	Ret(ErrorCode),
}

#[derive(Debug)]
pub enum Error {
	Sgxs(SgxsError),
	Create(SgxIoctlError),
	Add(SgxIoctlError),
	Init(SgxIoctlError),
	Destroy(SgxIoctlError),
	ChunksNotSupported,
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
	tcss: Vec<Tcs>,
	base: u64,
}

impl<'a> Drop for Mapping<'a> {
	fn drop(&mut self) {
		let _=self.destroy();
	}
}

impl<'a> Map for Mapping<'a> {
	fn base_address(&self) -> Address {
		::private::loader::make_address(self.base)
	}

	fn tcss(&mut self) -> &mut [Tcs] {
		&mut self.tcss
	}
}

impl<'a> Mapping<'a> {
	fn create(dev: &'a Device, ecreate: MeasECreate, sigstruct: &Sigstruct, einittoken: &Einittoken) -> Result<Mapping<'a>> {
		let secs=Secs{
			size: ecreate.size,
			ssaframesize: ecreate.ssaframesize,
			miscselect: sigstruct.miscselect,
			attributes: if einittoken.valid==1 { einittoken.attributes.clone() } else { sigstruct.attributes.clone() },
			..Default::default()
		};
		let mut createdata=ioctl::CreateData{
			secs:&secs,
			base:0
		};
		try_ioctl_unsafe!(Create,ioctl::create(dev.fd,&mut createdata));
		Ok(Mapping{device:dev,base:createdata.base,tcss:vec![]})
	}

	fn add(&mut self, page: (MeasEAdd,PageChunks,[u8;4096])) -> Result<()> {
		let (eadd,chunks,data)=page;
		let not_measured=match chunks.0 {
			0xffff => 0,
			0 => 1,
			_ => return Err(Error::ChunksNotSupported),
		};
		let secinfo=Secinfo{
			flags:eadd.secinfo.flags,
			..Default::default()
		};
		let adddata=ioctl::AddData{
			dstpage:self.base+eadd.offset,
			srcpage:&data,
			secinfo:&secinfo,
			not_measured:not_measured,
		};
		try_ioctl_unsafe!(Add,ioctl::add(self.device.fd,&adddata));
		if secinfo.flags.page_type()==PageType::Tcs as u8 {
			self.tcss.push(::private::loader::make_tcs(adddata.dstpage));
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

	fn destroy(&self) -> Result<()> {
		let destroydata=ioctl::DestroyData{
			base:self.base,
		};
		try_ioctl_unsafe!(Destroy,ioctl::destroy(self.device.fd,&destroydata));
		Ok(())
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

		let mut mapping=try!(Mapping::create(self,ecreate,sigstruct,einittoken));

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
