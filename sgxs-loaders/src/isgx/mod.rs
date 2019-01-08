/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod ioctl;

use libc;
use std::fs::{File, OpenOptions};
use std::io::{Error as IoError, Result as IoResult};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use abi::{Attributes, Einittoken, ErrorCode, Miscselect, Secinfo, Secs, Sigstruct};
use sgxs_crate::einittoken::EinittokenProvider;
use sgxs_crate::loader;
use sgxs_crate::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};

use crate::{MappingInfo, Tcs};
use generic::{self, EinittokenError, EnclaveLoad, Mapping};

pub const DEFAULT_DEVICE_PATH: &'static str = "/dev/isgx";

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

impl EinittokenError for Error {
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

impl EnclaveLoad for InnerDevice {
    type Error = Error;

    fn new(
        device: Arc<InnerDevice>,
        ecreate: MeasECreate,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> Result<Mapping<Self>, Self::Error> {
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                ecreate.size as usize,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_SHARED,
                device.fd.as_raw_fd(),
                0,
            )
        };
        if ptr.is_null() || ptr == libc::MAP_FAILED {
            return Err(Error::Map(IoError::last_os_error()));
        }
        let mapping = Mapping {
            device,
            base: ptr as u64,
            size: ecreate.size,
            tcss: vec![],
        };

        let secs = Secs {
            baseaddr: mapping.base,
            size: ecreate.size,
            ssaframesize: ecreate.ssaframesize,
            miscselect,
            attributes,
            ..Default::default()
        };
        let createdata = ioctl::CreateData { secs: &secs };
        try_ioctl_unsafe!(
            Create,
            ioctl::create(mapping.device.fd.as_raw_fd(), &createdata)
        );
        Ok(mapping)
    }

    fn add(
        mapping: &mut Mapping<Self>,
        page: (MeasEAdd, PageChunks, [u8; 4096]),
    ) -> Result<(), Self::Error> {
        let (eadd, chunks, data) = page;
        let secinfo = Secinfo {
            flags: eadd.secinfo.flags,
            ..Default::default()
        };
        let adddata = ioctl::AddData {
            dstpage: mapping.base + eadd.offset,
            srcpage: &data,
            secinfo: &secinfo,
            chunks: chunks.0,
        };
        try_ioctl_unsafe!(Add, ioctl::add(mapping.device.fd.as_raw_fd(), &adddata));

        Ok(())
    }

    fn init(
        mapping: &Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        let initdata = ioctl::InitData {
            base: mapping.base,
            sigstruct,
            einittoken: match einittoken {
                None => &Einittoken::default(),
                Some(t) => t,
            },
        };
        try_ioctl_unsafe!(Init, ioctl::init(mapping.device.fd.as_raw_fd(), &initdata));
        Ok(())
    }

    fn destroy(mapping: &mut Mapping<Self>) {
        unsafe { libc::munmap(mapping.base as usize as *mut _, mapping.size as usize) };
    }
}

#[derive(Debug)]
struct InnerDevice {
    fd: File,
}

#[derive(Debug)]
pub struct Device {
    inner: generic::Device<InnerDevice>,
}

pub struct DeviceBuilder {
    inner: generic::DeviceBuilder<InnerDevice>,
}

impl Device {
    pub fn open<T: AsRef<Path>>(path: T) -> IoResult<DeviceBuilder> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(DeviceBuilder {
            inner: generic::DeviceBuilder {
                device: generic::Device {
                    inner: Arc::new(InnerDevice { fd: file }),
                    einittoken_provider: None,
                },
            },
        })
    }
}

impl loader::Load for Device {
    type MappingInfo = MappingInfo;
    type Tcs = Tcs;

    fn load<R: SgxsRead>(
        &mut self,
        reader: &mut R,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> ::std::result::Result<loader::Mapping<Self>, ::failure::Error> {
        self.inner
            .load(reader, sigstruct, attributes, miscselect)
            .map(Into::into)
    }
}

impl DeviceBuilder {
    pub fn einittoken_provider<P: Into<Box<EinittokenProvider>>>(
        mut self,
        einittoken_provider: P,
    ) -> Self {
        self.inner.einittoken_provider(einittoken_provider.into());
        self
    }

    pub fn build(self) -> Device {
        Device {
            inner: self.inner.build(),
        }
    }
}
