/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod ioctl;

use libc;
use std::fs::{File, OpenOptions};
use std::io::{Error as IoError, Result as IoResult};
use std::os::raw::c_void;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use failure::ResultExt;

use sgxs_crate::einittoken::EinittokenProvider;
use sgxs_crate::loader;
use sgxs_crate::sgxs::{
    CreateInfo, Error as SgxsError, MeasEAdd, MeasECreate, PageChunks, PageReader, SgxsRead,
};

use abi::{Attributes, Einittoken, ErrorCode, Miscselect, PageType, Secinfo, Secs, Sigstruct};

pub const DEFAULT_DEVICE_PATH: &'static str = "/dev/isgx";

#[derive(Debug)]
pub struct Tcs {
    _mapping: Arc<Mapping>,
    address: u64,
}

impl loader::Tcs for Tcs {
    fn address(&self) -> *mut c_void {
        self.address as _
    }
}

#[derive(Fail, Debug)]
pub enum SgxIoctlError {
    #[fail(display = "I/O ctl failed.")]
    Io(#[cause] IoError),
    #[fail(display = "The SGX instruction returned an error: {:?}.", _0)]
    Ret(ErrorCode),
    #[fail(display = "The enclave was destroyed because the CPU was powered down.")]
    PowerLostEnclave,
    #[fail(display = "Launch enclave version rollback detected.")]
    LeRollback,
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Failed to map enclave into memory.")]
    Map(#[cause] IoError),
    #[fail(display = "Failed to call ECREATE.")]
    Create(#[cause] SgxIoctlError),
    #[fail(display = "Failed to call EADD.")]
    Add(#[cause] SgxIoctlError),
    #[fail(display = "Failed to call EINIT.")]
    Init(#[cause] SgxIoctlError),
}

impl Error {
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
        const SGX_POWER_LOST_ENCLAVE: i32 = 0x40000000;
        const SGX_LE_ROLLBACK: i32 = 0x40000001;

        match unsafe { $v } {
            Err(_) => return Err(Error::$f(SgxIoctlError::Io(IoError::last_os_error()))),
            Ok(0) => (),
            Ok(SGX_POWER_LOST_ENCLAVE) => return Err(Error::$f(SgxIoctlError::PowerLostEnclave)),
            Ok(SGX_LE_ROLLBACK) => return Err(Error::$f(SgxIoctlError::LeRollback)),
            Ok(v) => {
                return Err(Error::$f(SgxIoctlError::Ret(
                    ErrorCode::from_repr(v as u32).expect("Invalid ioctl return value"),
                )))
            }
        }
    }};
}

#[derive(Debug)]
struct Mapping {
    device: Arc<InnerDevice>,
    tcss: Vec<u64>,
    base: u64,
    size: u64,
}

#[derive(Debug)]
pub struct MappingInfo {
    mapping: Arc<Mapping>,
}

impl loader::MappingInfo for MappingInfo {
    fn address(&self) -> *mut c_void {
        self.mapping.base as _
    }

    fn size(&self) -> usize {
        self.mapping.size as _
    }
}

impl Mapping {
    fn new(dev: Arc<InnerDevice>, size: u64) -> Result<Mapping> {
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size as usize,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_SHARED,
                dev.fd.as_raw_fd(),
                0,
            )
        };
        if ptr == ptr::null_mut() || ptr == libc::MAP_FAILED {
            Err(Error::Map(IoError::last_os_error()))
        } else {
            Ok(Mapping {
                device: dev,
                base: ptr as u64,
                size: size,
                tcss: vec![],
            })
        }
    }

    fn create(
        &mut self,
        ecreate: MeasECreate,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> Result<()> {
        let size = ecreate.size; // aligned copy
        assert_eq!(self.size, size);
        let secs = Secs {
            baseaddr: self.base,
            size: ecreate.size,
            ssaframesize: ecreate.ssaframesize,
            miscselect,
            attributes,
            ..Default::default()
        };
        let createdata = ioctl::CreateData { secs: &secs };
        try_ioctl_unsafe!(
            Create,
            ioctl::create(self.device.fd.as_raw_fd(), &createdata)
        );
        Ok(())
    }

    fn add(&mut self, page: (MeasEAdd, PageChunks, [u8; 4096])) -> Result<()> {
        let (eadd, chunks, data) = page;
        let secinfo = Secinfo {
            flags: eadd.secinfo.flags,
            ..Default::default()
        };
        let adddata = ioctl::AddData {
            dstpage: self.base + eadd.offset,
            srcpage: &data,
            secinfo: &secinfo,
            chunks: chunks.0,
        };
        try_ioctl_unsafe!(Add, ioctl::add(self.device.fd.as_raw_fd(), &adddata));

        if secinfo.flags.page_type() == PageType::Tcs as u8 {
            self.tcss.push(adddata.dstpage);
        }

        Ok(())
    }

    fn init(&self, sigstruct: &Sigstruct, einittoken: &Einittoken) -> Result<()> {
        let initdata = ioctl::InitData {
            base: self.base,
            sigstruct: sigstruct,
            einittoken: einittoken,
        };
        try_ioctl_unsafe!(Init, ioctl::init(self.device.fd.as_raw_fd(), &initdata));
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base as usize as *mut _, self.size as usize) };
    }
}

#[derive(Debug)]
struct InnerDevice {
    fd: File,
}

pub struct Device<P> {
    inner: Arc<InnerDevice>,
    einittoken_provider: P,
}

impl<P> Device<P> {
    pub fn open<T: AsRef<Path>>(path: T, einittoken_provider: P) -> IoResult<Device<P>> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Device {
            inner: Arc::new(InnerDevice { fd: file }),
            einittoken_provider,
        })
    }
}

impl<P: EinittokenProvider> loader::Load for Device<P> {
    type MappingInfo = MappingInfo;
    type Tcs = Tcs;

    fn load<R: SgxsRead>(
        &mut self,
        reader: &mut R,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> ::std::result::Result<loader::Mapping<Self>, ::failure::Error> {
        let einittoken = self
            .einittoken_provider
            .token(sigstruct, attributes, false)
            .context("The EINITTOKEN provider didn't provide a token")?;

        let (CreateInfo { ecreate, sized }, mut reader) = try!(PageReader::new(reader));

        if !sized {
            return Err(SgxsError::StreamUnsized.into());
        }

        let mut mapping = try!(Mapping::new(self.inner.clone(), ecreate.size));

        try!(mapping.create(ecreate, attributes, miscselect));

        loop {
            match try!(reader.read_page()) {
                Some(page) => try!(mapping.add(page)),
                None => break,
            }
        }

        match mapping.init(sigstruct, &einittoken) {
            Err(ref e) if e.is_einittoken_error() => {
                let einittoken = self
                    .einittoken_provider
                    .token(sigstruct, attributes, true)
                    .context("The EINITTOKEN provider didn't provide a token")?;
                mapping.init(sigstruct, &einittoken)?
            }
            v => v?,
        }

        let mapping = Arc::new(mapping);

        Ok(loader::Mapping {
            tcss: mapping
                .tcss
                .iter()
                .map(|&tcs| Tcs {
                    _mapping: mapping.clone(),
                    address: tcs,
                })
                .collect(),
            info: MappingInfo { mapping },
        })
    }
}
