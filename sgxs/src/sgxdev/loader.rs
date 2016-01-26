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

use std::ops::Add;
use std::mem::transmute;
use std::marker::PhantomData;
use std::any::Any;
use std::cell::RefCell;
use std::borrow::{Borrow,BorrowMut};
use std::io::Error as IoError;

use libc;
use abi::*;
use sgxs::{self,PageReader,SgxsRead,MeasECreate};
use loader::EinittokenError;
use super::ioctl::*;
use super::Device;

// ==================================
// ========== useful types ==========
// ==================================

#[derive(Debug)]
pub enum Error {
	Sgxs(sgxs::Error),
	Io(IoError),
	TooManyPages,
	Sgx(Encls,ErrorCodes),
	Exception(Encls,u8,u64),
}

impl EinittokenError for Error {
	fn is_einittoken_error(&self) -> bool {
		use abi::ErrorCodes::*;
		use self::Error::*;
		match self {
			&Sgx(Encls::EInit,InvalidEinitToken) |
			&Sgx(Encls::EInit,InvalidCpusvn) |
			&Sgx(Encls::EInit,InvalidAttribute) | // InvalidEinitAttribute according to PR, but does not exist.
			&Sgx(Encls::EInit,InvalidMeasurement) => true,
			_ => false,
		}
	}
}

impl From<sgxs::Error> for Error {
    fn from(err: sgxs::Error) -> Error {
        Error::Sgxs(err)
    }
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Error {
        Error::Io(err)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Copy,Clone,Debug)]
pub struct Kaddr(pub u64);
#[derive(Copy,Clone,Debug)]
pub struct Uaddr(pub u64);

impl Add<u64> for Kaddr {
    type Output=Kaddr;
    fn add(self, rhs: u64) -> Kaddr {
		Kaddr(self.0+rhs)
	}
}

impl Add<u64> for Uaddr {
    type Output=Uaddr;
    fn add(self, rhs: u64) -> Uaddr {
		Uaddr(self.0+rhs)
	}
}

// ==================================================
// ========== safe storage of ioctl params ==========
// ==================================================

struct Pre<T>(T);

#[repr(C)]
#[unsafe_no_drop_flag]
pub struct RestrictedIoctlVecElem<'a>(pub IoctlVecElem,PhantomData<&'a Any>);

impl<'a> Drop for RestrictedIoctlVecElem<'a> {
	fn drop(&mut self) {}
}

#[allow(dead_code)]
fn assert_same_size_ioctlvecelem<'a>(a: IoctlVecElem) -> RestrictedIoctlVecElem<'a> {
	unsafe{::std::mem::transmute(a)}
}

impl<'a> From<IoctlVecElem> for RestrictedIoctlVecElem<'a> {
	fn from(ioctl_call: IoctlVecElem) -> RestrictedIoctlVecElem<'a> {
		RestrictedIoctlVecElem(ioctl_call,PhantomData)
	}
}

pub struct IoctlDataStore {
	ioctl_data: RefCell<Vec<Box<Any>>>,
}

impl IoctlDataStore {
	fn new() -> IoctlDataStore {
		IoctlDataStore{ioctl_data:RefCell::new(Vec::new())}
	}

	/// # Unsafe
	/// The user of the return value needs to make sure that it does not live
	/// longer than self.
	unsafe fn store<T: Any + Sized>(&self,data: T) -> u64 {
		let data=Box::new(data);
		let ret=&*data as *const T as usize as u64;
		self.ioctl_data.borrow_mut().push(data);
		ret
	}

	fn store_ecreate<'a>(&'a self, secinfo: Secinfo, secs: Secs, mut pageinfo: Pre<Pageinfo>, mut ioctl_call: Pre<IoctlVecElem>) -> RestrictedIoctlVecElem<'a> {
		unsafe {
			pageinfo.0.srcpge=self.store(secs);
			pageinfo.0.secinfo=self.store(secinfo);
			(ioctl_call.0.data.borrow_mut() as &mut EnclsDataIn).rbx=self.store(pageinfo.0);
			ioctl_call.0.into()
		}
	}

	fn store_eadd<'a>(&'a self, secinfo: Secinfo, data: [u8;4096], mut pageinfo: Pre<Pageinfo>, mut ioctl_call: Pre<IoctlVecElem>) -> RestrictedIoctlVecElem<'a> {
		unsafe {
			pageinfo.0.srcpge=self.store(data);
			pageinfo.0.secinfo=self.store(secinfo);
			(ioctl_call.0.data.borrow_mut() as &mut EnclsDataIn).rbx=self.store(pageinfo.0);
			ioctl_call.0.into()
		}
	}
}

// ===============================================
// ========== building ENCLS parameters ==========
// ===============================================

fn prepare_ecreate(addr: Kaddr, base: Uaddr, size: u64, ssaframesize: u32, sigstruct: &Sigstruct, einittoken: &Einittoken) -> (Secinfo,Secs,Pre<Pageinfo>,Pre<IoctlVecElem>) {
	let secinfo=Secinfo{
		flags:secinfo_flags::R|secinfo_flags::W|SecinfoFlags::from(PageType::Secs),
		..Default::default()
	};
	let secs=Secs{
		size: size,
		baseaddr: base.0,
		ssaframesize: ssaframesize,
		miscselect: sigstruct.miscselect,
		attributes: if einittoken.valid==1 { einittoken.attributes.clone() } else { sigstruct.attributes.clone() },
		isvprodid: sigstruct.isvprodid,
		isvsvn: sigstruct.isvsvn,
		..Default::default()
	};
	let pageinfo=Pre(Pageinfo{
		srcpge: !0,
		secinfo: !0,
		secs: 0,
		linaddr: 0,
	});
	let ioctl_call=Pre(IoctlVecElem{
		leaf: Encls::ECreate as i32,
		return_flag: EXCEPTION,
		data: EnclsData::from(EnclsDataIn{
			rbx: !0,
			rcx: addr.0,
			..Default::default()
		}),
	});
	(secinfo,secs,pageinfo,ioctl_call)
}

fn prepare_eadd(k_addr: Kaddr, u_addr: Uaddr, secs: Kaddr, secinfo_flags_: SecinfoFlags) -> (Secinfo,Pre<Pageinfo>,Pre<IoctlVecElem>) {
	let secinfo=Secinfo{
		flags:secinfo_flags_,
		..Default::default()
	};
	let pageinfo=Pre(Pageinfo{
		srcpge: !0,
		secinfo: !0,
		secs: secs.0,
		linaddr: u_addr.0,
	});
	let ioctl_call=Pre(IoctlVecElem{
		leaf: Encls::EAdd as i32,
		return_flag: EXCEPTION,
		data: EnclsData::from(EnclsDataIn{
			rbx: !0,
			rcx: k_addr.0,
			..Default::default()
		}),
	});

	let mut prot=libc::PROT_NONE;
	if secinfo.flags.page_type()==PageType::Tcs {
			prot=libc::PROT_READ|libc::PROT_WRITE;
	} else {
		if secinfo.flags.contains(secinfo_flags::R) {
			prot|=libc::PROT_READ;
		}
		if secinfo.flags.contains(secinfo_flags::W) {
			prot|=libc::PROT_WRITE;
		}
		if secinfo.flags.contains(secinfo_flags::X) {
			prot|=libc::PROT_EXEC;
		}
	}

	unsafe{libc::mprotect(u_addr.0 as usize as *mut _,0x1000,prot)};

	(secinfo,pageinfo,ioctl_call)
}

fn prepare_eextend(addr: Kaddr, secs: Kaddr) -> IoctlVecElem {
	IoctlVecElem{
		leaf: Encls::EExtend as i32,
		return_flag: EXCEPTION,
		data: EnclsData::from(EnclsDataIn{
			rbx: secs.0,
			rcx: addr.0,
			..Default::default()
		}),
	}
}

fn prepare_einit<'a>(secs: Kaddr, sigstruct: &'a Sigstruct, einittoken: &'a Einittoken) -> RestrictedIoctlVecElem<'a> {
	IoctlVecElem{
		leaf: Encls::EInit as i32,
		return_flag: EXCEPTION|ERROR,
		data: EnclsData::from(EnclsDataIn{
			rcx: secs.0,
			rbx: sigstruct as *const _ as u64,
			rdx: einittoken as *const _ as u64,
			..Default::default()
		}),
	}.into()
}

fn prepare_eremove(addr: Kaddr) -> IoctlVecElem {
	IoctlVecElem{
		leaf: Encls::ERemove as i32,
		return_flag: EXCEPTION,
		data: EnclsData::from(EnclsDataIn{
			rcx: addr.0,
			..Default::default()
		}),
	}
}

// ================================
// ========== public API ==========
// ================================

pub struct Pages<'a> {
	device: &'a Device,
	pages: Vec<Kaddr>,
}

impl<'a> Drop for Pages<'a> {
	fn drop(&mut self) {
		let mut ioctls=self.pages.iter().rev().cloned().map(prepare_eremove).collect::<Vec<_>>();

		let mut ioctl_param=IoctlVec{num:ioctls.len() as i32,ioctls:ioctls.as_mut_ptr() as *mut _};
		let ret=unsafe{multi_encls(self.device.fd,&mut ioctl_param)} as i32;

		if ret<0 {
			panic!("Syscall error while freeing SGX pages: {}",IoError::from_raw_os_error(-ret))
		}

		for ioctl_call in ioctls {
			let dout: &EnclsDataOut=ioctl_call.data.borrow();
			if dout.exception!=-1 {
				panic!("Exception while freeing SGX pages")
			}
		}
	}
}

pub fn load<'dev,'rd, R: SgxsRead + 'rd>(dev: &'dev Device, mut reader: PageReader<'rd,R>, ecreate: MeasECreate, base: Uaddr, k_base: Kaddr, secs: Kaddr, sigstruct: &Sigstruct, einittoken: Option<&Einittoken>) -> Result<(Vec<Uaddr>,Pages<'dev>)> {
	let einittoken_default;
	let einittoken=einittoken.unwrap_or({einittoken_default=Default::default();&einittoken_default});
	let ioctl_data=IoctlDataStore::new();
	let mut ioctls=vec![];
	let mut pages=vec![];
	let mut tcss=vec![];

	{	let (secinfo,secs,pageinfo,ioctl_call)=prepare_ecreate(secs,base,ecreate.size,ecreate.ssaframesize,&sigstruct,&einittoken);
		ioctls.push(ioctl_data.store_ecreate(secinfo,secs,pageinfo,ioctl_call)); }
	pages.push(secs);

	loop {
		if let Some((eadd,chunks,data))=try!(reader.read_page()) {
			{	let (secinfo,pageinfo,ioctl_call)=prepare_eadd(k_base+eadd.offset,base+eadd.offset,secs,eadd.secinfo.flags);
				ioctls.push(ioctl_data.store_eadd(secinfo,data,pageinfo,ioctl_call)); }
			pages.push(k_base+eadd.offset);
			if eadd.secinfo.flags.page_type()==PageType::Tcs {
				tcss.push(base+eadd.offset);
			}
			for chunk in 0..16 {
				if (chunks.0&(1<<chunk))!=0 {
					ioctls.push(prepare_eextend(k_base+eadd.offset+256*chunk,secs).into());
				}
			}
		} else {
			break;
		}
	}

	ioctls.push(prepare_einit(secs,sigstruct,einittoken));

	if ioctls.len()>(::std::i32::MAX as usize) {
		return Err(Error::TooManyPages);
	}

	let mut ioctl_param=IoctlVec{num:ioctls.len() as i32,ioctls:ioctls.as_mut_ptr() as *mut _};
	let ret=unsafe{multi_encls(dev.fd,&mut ioctl_param)} as i32;

	if ret<0 {
		return Err(IoError::from_raw_os_error(-ret).into());
	}

	let pages=Pages{device:dev,pages:pages};

	for ioctl_call in ioctls {
		let dout: &EnclsDataOut=ioctl_call.0.data.borrow();
		if dout.exception!=-1 {
			return Err(Error::Exception(unsafe{transmute(ioctl_call.0.leaf)},dout.exception as u8,dout.data));
		} else if ioctl_call.0.return_flag.contains(ERROR) && dout.data!=0 {
			return Err(unsafe{Error::Sgx(transmute(ioctl_call.0.leaf),transmute(dout.data as u32))});
		}
	}

	Ok((tcss,pages))
}
