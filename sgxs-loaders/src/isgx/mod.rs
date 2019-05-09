/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod ioctl;

use libc;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, Error as IoError, Result as IoResult};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use abi::{Attributes, Einittoken, ErrorCode, Miscselect, Secinfo, Secs, Sigstruct};
use sgxs_crate::einittoken::EinittokenProvider;
use sgxs_crate::loader;
use sgxs_crate::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};

use crate::{MappingInfo, Tcs};
use generic::{self, EinittokenError, EnclaveLoad, Mapping};

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

macro_rules! ioctl_unsafe {
    ( $f:ident, $v:expr ) => {{
        const SGX_POWER_LOST_ENCLAVE: i32 = 0x40000000;
        const SGX_LE_ROLLBACK: i32 = 0x40000001;

        match unsafe { $v } {
            Err(_) => Err(Error::$f(SgxIoctlError::Io(IoError::last_os_error()))),
            Ok(0) => Ok(()),
            Ok(SGX_POWER_LOST_ENCLAVE) => Err(Error::$f(SgxIoctlError::PowerLostEnclave)),
            Ok(SGX_LE_ROLLBACK) => Err(Error::$f(SgxIoctlError::LeRollback)),
            Ok(v) => Err(Error::$f(SgxIoctlError::Ret(
                ErrorCode::try_from(v as u32).expect("Invalid ioctl return value"),
            ))),
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
        ioctl_unsafe!(
            Create,
            ioctl::create(mapping.device.fd.as_raw_fd(), &createdata)
        )?;
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
        ioctl_unsafe!(Add, ioctl::add(mapping.device.fd.as_raw_fd(), &adddata))
    }

    fn init(
        mapping: &Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        // ioctl() may return ENOTTY if the specified request does not apply to
        // the kind of object that the descriptor fd references.
        fn is_enotty(result: &Result<(), Error>) -> bool {
            match result {
                Err(Error::Init(SgxIoctlError::Io(ref err))) => {
                    err.raw_os_error() == Some(libc::ENOTTY)
                }
                _ => false,
            }
        }

        fn ioctl_init(mapping: &Mapping<InnerDevice>, sigstruct: &Sigstruct) -> Result<(), Error> {
            let initdata = ioctl::InitData {
                base: mapping.base,
                sigstruct,
            };
            ioctl_unsafe!(Init, ioctl::init(mapping.device.fd.as_raw_fd(), &initdata))
        }

        fn ioctl_init_with_token(
            mapping: &Mapping<InnerDevice>,
            sigstruct: &Sigstruct,
            einittoken: &Einittoken,
        ) -> Result<(), Error> {
            let initdata = ioctl::InitDataWithToken {
                base: mapping.base,
                sigstruct,
                einittoken,
            };
            ioctl_unsafe!(
                Init,
                ioctl::init_with_token(mapping.device.fd.as_raw_fd(), &initdata)
            )
        }

        // Try either EINIT ioctl(), in the order that makes most sense given
        // the function arguments
        if let Some(einittoken) = einittoken {
            let res = ioctl_init_with_token(mapping, sigstruct, einittoken);

            if is_enotty(&res) {
                ioctl_init(mapping, sigstruct)
            } else {
                res
            }
        } else {
            let res = ioctl_init(mapping, sigstruct);

            if is_enotty(&res) {
                ioctl_init_with_token(mapping, sigstruct, &Default::default())
            } else {
                res
            }
        }
    }

    fn destroy(mapping: &mut Mapping<Self>) {
        unsafe { libc::munmap(mapping.base as usize as *mut _, mapping.size as usize) };
    }
}

#[derive(Debug)]
struct InnerDevice {
    fd: File,
    path: PathBuf,
}

#[derive(Debug)]
pub struct Device {
    inner: generic::Device<InnerDevice>,
}

pub struct DeviceBuilder {
    inner: generic::DeviceBuilder<InnerDevice>,
}

impl Device {
    /// Open `/dev/isgx`, or if that doesn't exist, `/dev/sgx`.
    pub fn new() -> IoResult<DeviceBuilder> {
        const DEFAULT_DEVICE_PATH1: &'static str = "/dev/isgx";
        const DEFAULT_DEVICE_PATH2: &'static str = "/dev/sgx";

        match Self::open(DEFAULT_DEVICE_PATH1) {
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => Self::open(DEFAULT_DEVICE_PATH2),
            v => v,
        }
    }

    pub fn open<T: AsRef<Path>>(path: T) -> IoResult<DeviceBuilder> {
        let path = path.as_ref();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(DeviceBuilder {
            inner: generic::DeviceBuilder {
                device: generic::Device {
                    inner: Arc::new(InnerDevice {
                        fd: file,
                        path: path.to_owned(),
                    }),
                    einittoken_provider: None,
                },
            },
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.inner.path
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
